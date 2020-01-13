import * as rlp from 'rlp'
import {
  toBuffer,
  baToJSON,
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

interface AccountProps {
  nonce: Buffer
  balance: Buffer
  stateRoot: Buffer
  codeHash: Buffer
}

// Would prefer for Account class getters to have type `Buffer`
// and setters to have type `any` to be cast `toBuffer`,
// however get ts error:
// `'get' and 'set' accessor must have the same type`
type BufferLike = Buffer | any

export default class Account {
  private props: AccountProps

  /**
   * The account's nonce.
   */
  get nonce(): BufferLike {
    return this.props.nonce
  }

  set nonce(nonce: BufferLike) {
    this.props.nonce = toBuffer(nonce)
  }

  /**
   * The account's balance in wei.
   */
  get balance(): BufferLike {
    return this.props.balance
  }

  set balance(balance: BufferLike) {
    this.props.balance = toBuffer(balance)
  }

  /**
   * The stateRoot for the storage of the contract.
   */
  get stateRoot(): BufferLike {
    return this.props.stateRoot
  }

  set stateRoot(stateRoot: BufferLike) {
    stateRoot = toBuffer(stateRoot)

    if (stateRoot.length !== 32) {
      throw new Error('The field stateRoot must be exactly 32 bytes.')
    }

    this.props.stateRoot = stateRoot
  }

  /**
   * The hash of the code of the contract.
   */
  get codeHash(): Buffer {
    return this.props.codeHash
  }

  /**
   * @deprecated
   */
  get raw(): Array<Buffer> {
    const { nonce, balance, stateRoot, codeHash } = this.props
    return [nonce, balance, stateRoot, codeHash]
  }

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

      data.forEach((value, i) => {
        switch (i) {
          case 0:
            nonce = toBuffer(value)
          case 1:
            balance = toBuffer(value)
          case 2:
            stateRoot = toBuffer(value)
          case 3:
            codeHash = toBuffer(value)
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

    this.props = {
      nonce: toBuffer(nonce || '0x'),
      balance: toBuffer(balance || '0x'),
      stateRoot: stateRoot ? toBuffer(stateRoot) : KECCAK256_RLP,
      codeHash: codeHash ? toBuffer(codeHash) : KECCAK256_NULL,
    }

    // Validate
    if (this.props.stateRoot.length !== 32) {
      throw new Error('The field stateRoot must be exactly 32 bytes.')
    } else if (this.props.codeHash.length !== 32) {
      throw new Error('The field codeHash must be exactly 32 bytes.')
    }
  }

  /**
   * Returns the RLP serialization of the account as a `Buffer`.
   */
  serialize(): Buffer {
    const { nonce, balance, stateRoot, codeHash } = this.props
    return rlp.encode([nonce, balance, stateRoot, codeHash])
  }

  /**
   * Returns a JSON representation of the object.
   * @param label If output should be formatted as a labled object.
   */
  toJSON(label: boolean = false): String {
    const { nonce, balance, stateRoot, codeHash } = this.props
    if (label) {
      type Dict = { [key: string]: string }
      const labeled: Dict = {
        nonce: `0x${nonce.toString('hex')}`,
        balance: `0x${balance.toString('hex')}`,
        stateRoot: `0x${stateRoot.toString('hex')}`,
        codeHash: `0x${codeHash.toString('hex')}`,
      }
      return JSON.stringify(labeled)
    }
    return baToJSON([nonce, balance, stateRoot, codeHash])
  }

  /**
   * Returns a `Boolean` deteremining if the account is a contract.
   *
   */
  isContract(): boolean {
    const { codeHash } = this.props
    return codeHash.toString('hex') !== KECCAK256_NULL_S
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

    trie.getRaw(this.props.codeHash, cb)
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
    const codeHash = keccak256(code)
    this.props.codeHash = codeHash

    if (codeHash.toString('hex') === KECCAK256_NULL_S) {
      cb(null, Buffer.alloc(0))
      return
    }

    trie.putRaw(codeHash, code, (err: any) => {
      cb(err, codeHash)
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
    t.root = this.props.stateRoot
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
    t.root = this.props.stateRoot
    t.put(key, val, (err: any) => {
      if (err) return cb()
      this.props.stateRoot = t.root
      cb()
    })
  }

  /**
   * Returns a `Boolean` determining if the account is empty.
   *
   */
  isEmpty(): boolean {
    const { nonce, balance, codeHash } = this.props
    return (
      balance.toString('hex') === '' &&
      nonce.toString('hex') === '' &&
      codeHash.toString('hex') === KECCAK256_NULL_S
    )
  }
}
