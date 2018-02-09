const ethUtil = require('ethereumjs-util')
const rlp = require('rlp')
const Buffer = require('safe-buffer').Buffer

class Account {
  constructor (data) {
    // Define Properties
    let fields = [{
      name: 'nonce',
      default: Buffer.alloc(0)
    }, {
      name: 'balance',
      default: Buffer.alloc(0)
    }, {
      name: 'stateRoot',
      length: 32,
      default: ethUtil.SHA3_RLP
    }, {
      name: 'codeHash',
      length: 32,
      default: ethUtil.SHA3_NULL
    }]
  
    ethUtil.defineProperties(this, fields, data)
  }

  serialize () {
    return rlp.encode(this.raw)
  }

  isContract () {
    return this.codeHash.toString('hex') !== ethUtil.SHA3_NULL_S
  }

  getCode (state, cb) {
    if (!this.isContract()) {
      cb(null, Buffer.alloc(0))
      return
    }
  
    state.getRaw(this.codeHash, cb)
  }

  setCode (trie, code, cb) {
    let self = this
  
    this.codeHash = ethUtil.sha3(code)
  
    if (this.codeHash.toString('hex') === ethUtil.SHA3_NULL_S) {
      cb(null, Buffer.alloc(0))
      return
    }
  
    trie.putRaw(this.codeHash, code, function (err) {
      cb(err, self.codeHash)
    })
  }

  getStorage (trie, key, cb) {
    let t = trie.copy()
    t.root = this.stateRoot
    t.get(key, cb)
  }

  setStorage (trie, key, val, cb) {
    let self = this
    let t = trie.copy()
    t.root = self.stateRoot
    t.put(key, val, function (err) {
      if (err) return cb()
      self.stateRoot = t.root
      cb()
    })
  }

  isEmpty () {
    return this.balance.toString('hex') === '' &&
    this.nonce.toString('hex') === '' &&
    this.stateRoot.toString('hex') === ethUtil.SHA3_RLP_S &&
    this.codeHash.toString('hex') === ethUtil.SHA3_NULL_S
  }
}

module.exports = Account
