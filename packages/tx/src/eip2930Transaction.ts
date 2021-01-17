import { Address, BN, bnToRlp, ecrecover, ecsign, keccak256, rlp, unpadBuffer } from 'ethereumjs-util'
import { default as Transaction } from './transaction'

import { EIP2930TransactionData, EIP2930TxOptions} from './types'

const TYPED_TRANSACTION_ID = 1
const N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16)

// EIP-2930 Transaction format:
// 1 || rlp([chainId, nonce, gasPrice, gasLimit, to, value, data, access_list, yParity, senderR, senderS])
// This is the transaction which is returned if you decode the transaction when looking up the transaction hash.

// To hash a message:
// keccak256(rlp([1, chainId, nonce, gasPrice, gasLimit, to, value, data, access_list]))

// The ReceiptPayload:
// rlp([status, cumulativeGasUsed, logsBloom, logs])

// So the receipt should be encoded as 1 || rlp([status, cumulativeGasUsed, logsBloom, logs])

export class EIP2930Transaction extends Transaction {
    
    accessList: any
    yParity?: number
    chainId: number 

    // If this is called the transaction type is enforced to be 1.
    public static fromTxData(txData: EIP2930TransactionData, opts?: EIP2930TxOptions): EIP2930Transaction {
        return new EIP2930Transaction(txData, opts)
    }

    // Note: the TransactionType should be stripped of the serialized buffer.
    public static fromRlpSerializedTx(serialized: Buffer, opts?: EIP2930TxOptions): EIP2930Transaction {

        const values = rlp.decode(serialized)

        if (!Array.isArray(values)) {
        throw new Error('Invalid serialized tx input. Must be array')
        }

        return this.fromValuesArray(values, opts)
    }

    // Values array is assumed to have the TransactionPayload elements, so no TransactionType at the first index.
    public static fromValuesArray(values: Buffer[], opts?: EIP2930TxOptions): EIP2930Transaction {

        if (values.length !== 8 && values.length !== 11) {
            throw new Error(
              'Invalid transaction. Only expecting 8 values (for unsigned tx) or 11 values (for signed tx).'
            )
          }
      
          const [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, yParity, r, s] = values
      
          const emptyBuffer = Buffer.from([])
      
          return new EIP2930Transaction(
            {
              nonce: new BN(nonce),
              gasPrice: new BN(gasPrice),
              gasLimit: new BN(gasLimit),
              to: to && to.length > 0 ? new Address(to) : undefined,
              value: new BN(value),
              data: data ?? emptyBuffer,
              r: !r?.equals(emptyBuffer) ? new BN(r) : undefined,
              s: !s?.equals(emptyBuffer) ? new BN(s) : undefined,
              transactionType: 1,
              yParity,
              accessList,
              chainId
            },
            opts
          )
    }

    constructor(txData: EIP2930TransactionData, opts?: EIP2930TxOptions) {
        super(txData, opts) 

        const chainIdNumber = parseInt((<Buffer>txData.chainId).toString('hex'), 16)

        if (!(chainIdNumber === this.common.chainId())) {
            throw new Error("Chain ID violation")
        }

        // verify the access list items 

        for (let index = 0; index < txData.accessList.length; index++) {
            let item = txData.accessList.item 
            let address: Buffer = item[0]
            if (address.length != 20) {
                throw new Error("Address does not have length 20")
            }
            let storageKeys: Buffer[] = item[1]


            for (let storageIndex = 0; index < storageKeys.length; storageIndex++) {
                let storageKey = storageKeys[storageIndex]

                if (storageKey.length != 32) {
                    throw new Error("Storage key length does not have length 32")
                }
            }
        }

        this.chainId = this.common.chainId() 
        this.accessList = txData.accessList
        
        if (txData.yParity) {
            this.yParity = parseInt((<Buffer>txData.yParity).toString('hex'), 16)
        }   
    }


  /**
   * Computes a sha3-256 hash of the serialized tx
   */
  hash(): Buffer {
    const values = [
      bnToRlp((new BN(this.chainId))),
      bnToRlp(this.nonce),
      bnToRlp(this.gasPrice),
      bnToRlp(this.gasLimit),
      this.to !== undefined ? this.to.buf : Buffer.from([]),
      bnToRlp(this.value),
      this.data,
      this.accessList,
      this.yParity ? bnToRlp(new BN(this.yParity)) : Buffer.from([]),
      this.r ? bnToRlp(this.r) : Buffer.from([]),
      this.s ? bnToRlp(this.s) : Buffer.from([]),
    ]

    const rlpValues = rlp.encode(values)
    const hashBuffer = Buffer.concat([Buffer.from("01", 'hex'), rlpValues])

    return keccak256(hashBuffer)
  }

  /* These methods can be used from the base class.
  getMessageToSign() {
    return this._getMessageToSign(this._unsignedTxImplementsEIP155())
  }

  getMessageToVerifySignature() {
    return this._getMessageToSign(this._signedTxImplementsEIP155())
  }

  getChainId(): number {
    return this.common.chainId()
  }
  */

/**
   * Returns the public key of the sender
   */
  getSenderPublicKey(): Buffer {
    const msgHash = this.getMessageToVerifySignature()

    // All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
    if (this.common.gteHardfork('homestead') && this.s && this.s.gt(N_DIV_2)) {
      throw new Error(
        'Invalid Signature: s-values greater than secp256k1n/2 are considered invalid'
      )
    }

    const { v, r, s } = this
    if (!v || !r || !s) {
      throw new Error('Missing values to derive sender public key from signed tx')
    }

    try {
      return ecrecover(
        msgHash,
        v.toNumber(),
        bnToRlp(r),
        bnToRlp(s),
      )
    } catch (e) {
      throw new Error('Invalid Signature')
    }
  }

  /**
   * Determines if the signature is valid
   */
  verifySignature(): boolean {
    try {
      // Main signature verification is done in `getSenderPublicKey()`
      const publicKey = this.getSenderPublicKey()
      return unpadBuffer(publicKey).length !== 0
    } catch (e) {
      return false
    }
  }

  /**
   * Sign a transaction with a given private key.
   * Returns a new Transaction object (the original tx will not be modified).
   * Example:
   * ```typescript
   * const unsignedTx = Transaction.fromTxData(txData)
   * const signedTx = unsignedTx.sign(privKey)
   * ```
   * @param privateKey Must be 32 bytes in length.
   */
  sign(privateKey: Buffer): EIP2930Transaction {
    if (privateKey.length !== 32) {
      throw new Error('Private key must be 32 bytes in length.')
    }

    const msgHash = this.getMessageToSign()

    // Only `v` is reassigned.
    /* eslint-disable-next-line prefer-const */
    let { v, r, s } = ecsign(msgHash, privateKey)

    const opts = {
      common: this.common,
    }

    return new EIP2930Transaction(
      {
        nonce: this.nonce,
        gasPrice: this.gasPrice,
        gasLimit: this.gasLimit,
        to: this.to,
        value: this.value,
        data: this.data,
        accessList: this.accessList,
        chainId: this.chainId,
        yParity: (v == 27 ? 0 : 1),
        transactionType: 1,
        r: new BN(r),
        s: new BN(s),
      },
      opts
    )
  }

  /**
   * The amount of gas paid for the data in this tx
   */
  getDataFee(): BN {
    const txDataZero = this.common.param('gasPrices', 'txDataZero')
    const txDataNonZero = this.common.param('gasPrices', 'txDataNonZero')

    let cost = 0
    for (let i = 0; i < this.data.length; i++) {
      this.data[i] === 0 ? (cost += txDataZero) : (cost += txDataNonZero)
    }
    return new BN(cost)
  }

  /**
   * The minimum amount of gas the tx must have (DataFee + TxFee + Creation Fee)
   */
  getBaseFee(): BN {
    const fee = this.getDataFee().addn(this.common.param('gasPrices', 'tx'))
    if (this.common.gteHardfork('homestead') && this.toCreationAddress()) {
      fee.iaddn(this.common.param('gasPrices', 'txCreation'))
    }
    return fee
  }

  /**
   * The up front amount that an account must have for this transaction to be valid
   */
  getUpfrontCost(): BN {
    return this.gasLimit.mul(this.gasPrice).add(this.value)
  }

  /**
   * Validates the signature and checks if
   * the transaction has the minimum amount of gas required
   * (DataFee + TxFee + Creation Fee).
   */
  validate(): boolean
  validate(stringError: false): boolean
  validate(stringError: true): string[]
  validate(stringError: boolean = false): boolean | string[] {
    const errors = []

    if (!this.verifySignature()) {
      errors.push('Invalid Signature')
    }

    if (this.getBaseFee().gt(this.gasLimit)) {
      errors.push(`gasLimit is too low. given ${this.gasLimit}, need at least ${this.getBaseFee()}`)
    }

    return stringError ? errors : errors.length === 0
  }

  /**
   * Returns a Buffer Array of the raw Buffers of this transaction, in order.
   */
  raw(): Buffer[] {
    return [
      bnToRlp(this.nonce),
      bnToRlp(this.gasPrice),
      bnToRlp(this.gasLimit),
      this.to !== undefined ? this.to.buf : Buffer.from([]),
      bnToRlp(this.value),
      this.data,
      this.v !== undefined ? bnToRlp(this.v) : Buffer.from([]),
      this.r !== undefined ? bnToRlp(this.r) : Buffer.from([]),
      this.s !== undefined ? bnToRlp(this.s) : Buffer.from([]),
    ]
  }

  /**
   * Returns the rlp encoding of the transaction.
   */
  serialize(): Buffer {
    return rlp.encode(this.raw())
  }

  /**
   * Returns an object with the JSON representation of the transaction
   */
  /* TODO: FIXME
  toJSON(): JsonTx {
    return {
      nonce: bnToHex(this.nonce),
      gasPrice: bnToHex(this.gasPrice),
      gasLimit: bnToHex(this.gasLimit),
      to: this.to !== undefined ? this.to.toString() : undefined,
      value: bnToHex(this.value),
      data: '0x' + this.data.toString('hex'),
      v: this.v !== undefined ? bnToHex(this.v) : undefined,
      r: this.r !== undefined ? bnToHex(this.r) : undefined,
      s: this.s !== undefined ? bnToHex(this.s) : undefined,
    }
  }
  */

  public isSigned(): boolean {
    const { yParity, r, s } = this
    return !!yParity && !!r && !!s
  }

  private _getMessageToSign(withEIP155: boolean) {
    const values = [
      bnToRlp(this.nonce),
      bnToRlp(this.gasPrice),
      bnToRlp(this.gasLimit),
      this.to !== undefined ? this.to.buf : Buffer.from([]),
      bnToRlp(this.value),
      this.data,
    ]

    if (withEIP155) {
      values.push(toBuffer(this.getChainId()))
      values.push(unpadBuffer(toBuffer(0)))
      values.push(unpadBuffer(toBuffer(0)))
    }

    return rlphash(values)
  }



}