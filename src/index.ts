import * as rlp from 'rlp'
import {
  toBuffer,
  keccak256,
  KECCAK256_RLP,
  KECCAK256_NULL,
  KECCAK256_NULL_S,
} from 'ethereumjs-util'

const Buffer = require('safe-buffer').Buffer

interface TrieGetCb {
  (err: any, value: Buffer | null): void
}
interface TriePutCb {
  (err?: any): void
}

interface Trie {
  root: Buffer
  copy(): Trie
  getRaw(key: Buffer, cb: TrieGetCb): void
  putRaw(key: Buffer | string, value: Buffer, cb: TriePutCb): void
  get(key: Buffer | string, cb: TrieGetCb): void
  put(key: Buffer | string, value: Buffer | string, cb: TriePutCb): void
}

export default class Account {
  /**
   * The account's nonce.
   */
  public nonce: Buffer

  /**
   * The account's balance in wei.
   */
  public balance: Buffer

  /**
   * The stateRoot for the storage of the contract.
   */
  public stateRoot: Buffer

  /**
   * The hash of the code of the contract.
   */
  public codeHash: Buffer

  /**
   * Creates a new account object
   *
   * ~~~
   * const data = [
   *   '0x02', // nonce
   *   '0x0384', // balance
   *   '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', // stateRoot
   *   '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', // codeHash
   * ]
   *
   * const data = {
   *   nonce: '',
   *   balance: '0x03e7',
   *   stateRoot: '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
   *   codeHash: '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
   * }
   *
   * const account = new Account(data)
   * ~~~
   *
   * @param data
   * An account can be initialized with either:
   * 1. A `buffer` containing the RLP serialized account.
   * 2. An `Array` of buffers relating to each of the account properties listed in order [nonce, balance, stateRoot, codeHash].
   * 3. An `object` with properties {nonce, balance, stateRoot, codeHash}.
   * For `Object` and `Array` each of the elements can either be a `Buffer`, hex `String`, `Number`, or an object with a `toBuffer` method such as `Bignum`.
   */
  constructor(data?: any) {
    let nonce
    let balance
    let stateRoot
    let codeHash

    if (typeof data === 'string') {
      data = Buffer.from(data.substring(0, 2) === '0x' ? data.substring(2) : data, 'hex')
    }

    if (Buffer.isBuffer(data)) {
      data = rlp.decode(data)
    }

    if (Array.isArray(data)) {
      if (data.length > 4) {
        throw new Error('wrong number of fields in data')
      }

      data.forEach((d, i) => {
        switch (i) {
          case 0:
            nonce = toBuffer(d)
          case 1:
            balance = toBuffer(d)
          case 2:
            stateRoot = toBuffer(d)
          case 3:
            codeHash = toBuffer(d)
        }
      })
    } else if (typeof data === 'object') {
      if (data.nonce) {
        nonce = toBuffer(data.nonce)
      }
      if (data.balance) {
        balance = toBuffer(data.balance)
      }
      if (data.stateRoot) {
        stateRoot = toBuffer(data.stateRoot)
      }
      if (data.codeHash) {
        codeHash = toBuffer(data.codeHash)
      }
    } else if (data) {
      throw new Error('invalid data')
    }

    this.nonce = toBuffer(nonce || '0x')
    this.balance = toBuffer(balance || '0x')
    this.stateRoot = stateRoot ? toBuffer(stateRoot) : KECCAK256_RLP
    this.codeHash = codeHash ? toBuffer(codeHash) : KECCAK256_NULL

    if (this.stateRoot.length !== 32) {
      throw new Error('The field stateRoot must be exactly 32 bytes.')
    } else if (this.codeHash.length !== 32) {
      throw new Error('The field codeHash must be exactly 32 bytes.')
    }
  }

  /**
   * Returns the RLP serialization of the account as a `Buffer`.
   *
   */
  serialize(): Buffer {
    return rlp.encode([this.nonce, this.balance, this.stateRoot, this.codeHash])
  }

  /**
   * Returns a `Boolean` deteremining if the account is a contract.
   *
   */
  isContract(): boolean {
    return this.codeHash.toString('hex') !== KECCAK256_NULL_S
  }

  /**
   * Fetches the code from the trie.
   * @param trie The [trie](https://github.com/ethereumjs/merkle-patricia-tree) storing the accounts
   * @param cb The callback
   */
  getCode(trie: Trie, cb: TrieGetCb): void {
    if (!this.isContract()) {
      cb(null, Buffer.alloc(0))
      return
    }

    trie.getRaw(this.codeHash, cb)
  }

  /**
   * Stores the code in the trie.
   *
   * ~~~
   * // Requires manual merkle-patricia-tree install
   * const SecureTrie = require('merkle-patricia-tree/secure')
   * const Account = require('./index.js').default
   *
   * let code = Buffer.from(
   * '73095e7baea6a6c7c4c2dfeb977efac326af552d873173095e7baea6a6c7c4c2dfeb977efac326af552d873157',
   * 'hex',
   * )
   *
   * let raw = {
   * nonce: '',
   * balance: '0x03e7',
   * stateRoot: '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
   * codeHash: '0xb30fb32201fe0486606ad451e1a61e2ae1748343cd3d411ed992ffcc0774edd4',
   * }
   * let account = new Account(raw)
   * let trie = new SecureTrie()
   *
   * account.setCode(trie, code, function(err, codeHash) {
   *   console.log(`Code with hash 0x${codeHash.toString('hex')} set to trie`)
   *   account.getCode(trie, function(err, code) {
   *     console.log(`Code ${code.toString('hex')} read from trie`)
   *   })
   * })
   * ~~~
   *
   * @param trie The [trie](https://github.com/ethereumjs/merkle-patricia-tree) storing the accounts.
   * @param {Buffer} code
   * @param cb The callback.
   *
   */
  setCode(trie: Trie, code: Buffer, cb: (err: any, codeHash: Buffer) => void): void {
    this.codeHash = keccak256(code)

    if (this.codeHash.toString('hex') === KECCAK256_NULL_S) {
      cb(null, Buffer.alloc(0))
      return
    }

    trie.putRaw(this.codeHash, code, (err: any) => {
      cb(err, this.codeHash)
    })
  }

  /**
   * Fetches `key` from the account's storage.
   * @param trie
   * @param key
   * @param cb
   */
  getStorage(trie: Trie, key: Buffer | string, cb: TrieGetCb) {
    const t = trie.copy()
    t.root = this.stateRoot
    t.get(key, cb)
  }

  /**
   * Stores a `val` at the `key` in the contract's storage.
   *
   * Example for `getStorage` and `setStorage`:
   *
   * ~~~
   * // Requires manual merkle-patricia-tree install
   * const SecureTrie = require('merkle-patricia-tree/secure')
   *  const Account = require('./index.js').default
   *
   * let raw = {
   *   nonce: '',
   *   balance: '0x03e7',
   *   stateRoot: '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421',
   *   codeHash: '0xb30fb32201fe0486606ad451e1a61e2ae1748343cd3d411ed992ffcc0774edd4',
   * }
   * let account = new Account(raw)
   * let trie = new SecureTrie()
   * let key = Buffer.from('0000000000000000000000000000000000000000', 'hex')
   * let value = Buffer.from('01', 'hex')
   *
   * account.setStorage(trie, key, value, function(err, value) {
   *   account.getStorage(trie, key, function(err, value) {
   *     console.log(`Value ${value.toString('hex')} set and retrieved from trie.`)
   *   })
   * })
   * ~~~
   *
   * @param trie
   * @param key
   * @param val
   * @param cb
   */
  setStorage(trie: Trie, key: Buffer | string, val: Buffer | string, cb: () => void) {
    const t = trie.copy()
    t.root = this.stateRoot
    t.put(key, val, (err: any) => {
      if (err) return cb()
      this.stateRoot = t.root
      cb()
    })
  }

  /**
   * Returns a `Boolean` determining if the account is empty.
   *
   */
  isEmpty(): boolean {
    return (
      this.balance.toString('hex') === '' &&
      this.nonce.toString('hex') === '' &&
      this.codeHash.toString('hex') === KECCAK256_NULL_S
    )
  }
}
