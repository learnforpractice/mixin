package kernel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/ioutil"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/mixin/network"
	"github.com/MixinNetwork/mixin/storage"
)

const (
	MempoolSize = 8192
)

type Node struct {
	IdForNetwork   crypto.Hash
	Account        common.Address
	ConsensusNodes map[crypto.Hash]*common.Node
	Graph          *RoundGraph
	TopoCounter    *TopologicalSequence
	SnapshotsPool  map[crypto.Hash][]*crypto.Signature
	SignaturesPool map[crypto.Hash]*crypto.Signature
	Peer           *network.Peer
	SyncPoints     *syncMap

	networkId   crypto.Hash
	store       storage.Store
	mempoolChan chan *common.Snapshot
	configDir   string
}

func SetupNode(store storage.Store, addr string, dir string) (*Node, error) {
	var node = &Node{
		ConsensusNodes: make(map[crypto.Hash]*common.Node),
		SnapshotsPool:  make(map[crypto.Hash][]*crypto.Signature),
		SignaturesPool: make(map[crypto.Hash]*crypto.Signature),
		SyncPoints:     &syncMap{mutex: new(sync.RWMutex), m: make(map[crypto.Hash]uint64)},
		store:          store,
		mempoolChan:    make(chan *common.Snapshot, MempoolSize),
		configDir:      dir,
		TopoCounter:    getTopologyCounter(store),
	}

	err := node.LoadNodeState()
	if err != nil {
		return nil, err
	}

	err = node.LoadGenesis(dir)
	if err != nil {
		return nil, err
	}

	err = node.LoadConsensusNodes()
	if err != nil {
		return nil, err
	}

	graph, err := LoadRoundGraph(node.store, node.networkId)
	if err != nil {
		return nil, err
	}
	node.Graph = graph

	node.Peer = network.NewPeer(node, node.IdForNetwork, addr)
	err = node.AddNeighborsFromConfig()
	if err != nil {
		return nil, err
	}

	logger.Printf("Listen:\t%s\n", addr)
	logger.Printf("Account:\t%s\n", node.Account.String())
	logger.Printf("View Key:\t%s\n", node.Account.PrivateViewKey.String())
	logger.Printf("Spend Key:\t%s\n", node.Account.PrivateSpendKey.String())
	logger.Printf("Network:\t%s\n", node.networkId.String())
	logger.Printf("Node Id:\t%s\n", node.IdForNetwork.String())
	logger.Printf("Topology:\t%d\n", node.TopoCounter.seq)
	return node, nil
}

func (node *Node) LoadNodeState() error {
	const stateKeyAccount = "account"
	var acc common.Address
	found, err := node.store.StateGet(stateKeyAccount, &acc)
	if err != nil {
		return err
	} else if !found {
		b := make([]byte, 32)
		_, err := rand.Read(b)
		if err != nil {
			panic(err)
		}
		acc = common.NewAddressFromSeed(b)
	}
	err = node.store.StateSet(stateKeyAccount, acc)
	if err != nil {
		return err
	}
	node.Account = acc
	return nil
}

func (node *Node) LoadConsensusNodes() error {
	nodes := node.store.ReadConsensusNodes()
	for _, cn := range nodes {
		logger.Println(cn.Account.String(), cn.State)
		if !cn.IsAccepted() {
			continue
		}
		idForNetwork := cn.Account.Hash().ForNetwork(node.networkId)
		node.ConsensusNodes[idForNetwork] = cn
	}
	return nil
}

func (node *Node) AddNeighborsFromConfig() error {
	f, err := ioutil.ReadFile(node.configDir + "/nodes.json")
	if err != nil {
		return err
	}
	var inputs []struct {
		Address string `json:"address"`
		Host    string `json:"host"`
	}
	err = json.Unmarshal(f, &inputs)
	if err != nil {
		return err
	}
	for _, in := range inputs {
		if in.Address == node.Account.String() {
			continue
		}
		acc, err := common.NewAddressFromString(in.Address)
		if err != nil {
			return err
		}
		node.Peer.AddNeighbor(acc.Hash().ForNetwork(node.networkId), in.Host)
	}

	return nil
}

func (node *Node) ListenNeighbors() error {
	return node.Peer.ListenNeighbors()
}

func (node *Node) NetworkId() crypto.Hash {
	return node.networkId
}

func (node *Node) BuildGraph() []*network.SyncPoint {
	return node.Graph.FinalCache
}

func (node *Node) BuildAuthenticationMessage() []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(time.Now().Unix()))
	hash := node.Account.Hash().ForNetwork(node.networkId)
	data = append(data, hash[:]...)
	sig := node.Account.PrivateSpendKey.Sign(data)
	return append(data, sig[:]...)
}

func (node *Node) Authenticate(msg []byte) (crypto.Hash, error) {
	ts := binary.BigEndian.Uint64(msg[:8])
	if time.Now().Unix()-int64(ts) > 3 {
		return crypto.Hash{}, errors.New("peer authentication message timeout")
	}

	var peerId crypto.Hash
	copy(peerId[:], msg[8:40])
	peer := node.ConsensusNodes[peerId]
	if peer == nil {
		return crypto.Hash{}, errors.New("peer authentication invalid consensus peer")
	}

	var sig crypto.Signature
	copy(sig[:], msg[40:])
	if peer.Account.PublicSpendKey.Verify(msg[:40], sig) {
		return peerId, nil
	}
	return crypto.Hash{}, errors.New("peer authentication message signature invalid")
}

func (node *Node) QueueAppendSnapshot(peerId crypto.Hash, s *common.Snapshot) error {
	s.Hash = s.PayloadHash()
	if len(s.Signatures) != 1 && !node.verifyFinalization(s.Signatures) {
		return node.Peer.SendSnapshotConfirmMessage(peerId, s.Hash, 0)
	}
	inNode, err := node.store.CheckTransactionInNode(s.NodeId, s.Transaction)
	if err != nil {
		return err
	}
	if inNode {
		node.Peer.ConfirmSnapshotForPeer(peerId, s.Hash, 1)
		return node.Peer.SendSnapshotConfirmMessage(peerId, s.Hash, 1)
	}

	sigs := make([]*crypto.Signature, 0)
	signaturesFilter := make(map[string]bool)
	signersMap := make(map[crypto.Hash]bool)
	for _, sig := range s.Signatures {
		if signaturesFilter[sig.String()] {
			continue
		}
		for idForNetwork, cn := range node.ConsensusNodes {
			if signersMap[idForNetwork] {
				continue
			}
			if cn.Account.PublicSpendKey.Verify(s.Hash[:], *sig) {
				sigs = append(sigs, sig)
				signersMap[idForNetwork] = true
				break
			}
		}
		signaturesFilter[sig.String()] = true
	}
	s.Signatures = sigs

	finalized := node.verifyFinalization(s.Signatures)
	if finalized {
		node.Peer.ConfirmSnapshotForPeer(peerId, s.Hash, 1)
		err := node.Peer.SendSnapshotConfirmMessage(peerId, s.Hash, 1)
		if err != nil {
			return err
		}
	} else {
		err := node.Peer.SendSnapshotConfirmMessage(peerId, s.Hash, 0)
		if err != nil || len(s.Signatures) != 1 {
			return err
		}
	}
	if signersMap[peerId] && (s.NodeId == node.IdForNetwork || signersMap[s.NodeId]) {
		if finalized {
			return node.store.QueueAppendSnapshot(peerId, s, finalized)
		} else if node.CheckSync() {
			return node.store.QueueAppendSnapshot(peerId, s, finalized)
		}
	}
	return nil
}

func (node *Node) SendTransactionToPeer(peerId, hash crypto.Hash) error {
	tx, err := node.store.ReadTransaction(hash)
	if err != nil {
		return err
	}
	if tx == nil {
		tx, err = node.store.CacheGetTransaction(hash)
		if err != nil || tx == nil {
			return err
		}
	}
	return node.Peer.SendTransactionMessage(peerId, tx)
}

func (node *Node) CachePutTransaction(tx *common.SignedTransaction) error {
	return node.store.CachePutTransaction(tx)
}

func (node *Node) ReadSnapshotsSinceTopology(offset, count uint64) ([]*common.SnapshotWithTopologicalOrder, error) {
	return node.store.ReadSnapshotsSinceTopology(offset, count)
}

func (node *Node) ReadSnapshotsForNodeRound(nodeIdWithNetwork crypto.Hash, round uint64) ([]*common.SnapshotWithTopologicalOrder, error) {
	return node.store.ReadSnapshotsForNodeRound(nodeIdWithNetwork, round)
}

func (node *Node) UpdateSyncPoint(peerId crypto.Hash, points []*network.SyncPoint) {
	if node.ConsensusNodes[peerId] == nil {
		return
	}
	for _, p := range points {
		if p.NodeId == node.IdForNetwork {
			node.SyncPoints.Set(peerId, p.Number)
		}
	}
}

func (node *Node) CheckSync() bool {
	if node.SyncPoints.Len() != len(node.ConsensusNodes)-1 {
		return false
	}
	final := node.Graph.FinalRound[node.IdForNetwork].Number
	for id, _ := range node.ConsensusNodes {
		if final < node.SyncPoints.Get(id) {
			return false
		}
	}
	return true
}

func (node *Node) ConsumeMempool() error {
	for {
		select {
		case s := <-node.mempoolChan:
			err := node.handleSnapshotInput(s)
			if err != nil {
				return err
			}
		}
	}
}

type syncMap struct {
	mutex *sync.RWMutex
	m     map[crypto.Hash]uint64
}

func (s *syncMap) Set(k crypto.Hash, v uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.m[k] = v
}

func (s *syncMap) Get(k crypto.Hash) uint64 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.m[k]
}

func (s *syncMap) Len() int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return len(s.m)
}
