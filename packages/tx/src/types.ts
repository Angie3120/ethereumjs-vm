import { AddressLike, BNLike, BufferLike } from 'ethereumjs-util'
import Common from '@ethereumjs/common'
import { Transaction } from '.'

/**
 * The options for initializing a Transaction.
 */
interface BaseTxOptions {
  /**
   * A Common object defining the chain and hardfork for the transaction.
   *
   * Default: `Common` object set to `mainnet` and the default hardfork as defined in the `Common` class.
   *
   * Current default hardfork: `istanbul`
   */
  common?: Common
  /**
   * A transaction object by default gets frozen along initialization. This gives you
   * strong additional security guarantees on the consistency of the tx parameters.
   *
   * If you need to deactivate the tx freeze - e.g. because you want to subclass tx and
   * add aditional properties - it is strongly encouraged that you do the freeze yourself
   * within your code instead.
   *
   * Default: true
   */
  freeze?: boolean
}

export interface EIP2930TxOptions extends BaseTxOptions {

}

export type TxOptions = BaseTxOptions | EIP2930TxOptions

/**
 * An object with an optional field with each of the transaction's values.
 */
export interface BaseTxData {
  /**
   * The transaction's nonce.
   */
  nonce?: BNLike

  /**
   * The transaction's gas price.
   */
  gasPrice?: BNLike

  /**
   * The transaction's gas limit.
   */
  gasLimit?: BNLike

  /**
   * The transaction's the address is sent to.
   */
  to?: AddressLike

  /**
   * The amount of Ether sent.
   */
  value?: BNLike

  /**
   * This will contain the data of the message or the init of a contract.
   */
  data?: BufferLike

  /**
   * EC recovery ID.
   */
  v?: BNLike

  /**
   * EC signature parameter.
   */
  r?: BNLike

  /**
   * EC signature parameter.
   */
  s?: BNLike
}

interface TypedTransactionData extends BaseTxData {
  transactionType: number
}

export interface EIP2930TransactionData extends TypedTransactionData {
  accessList: any // TODO: enforce this type
  yParity?: BufferLike,
  chainId: BufferLike
}

export type TxData = BaseTxData | EIP2930TransactionData




/**
 * An object with all of the transaction's values represented as strings.
 */
export interface JsonTx {
  nonce?: string
  gasPrice?: string
  gasLimit?: string
  to?: string
  data?: string
  v?: string
  r?: string
  s?: string
  value?: string
}

export interface BaseTransaction<TxDataType, TxOptionsType> {
  fromTxData(txData: TxDataType, opts?: TxOptionsType): BaseTransaction<TxDataType, TxOptionsType>
  fromRlpSerializedTx(serialized: Buffer, opts?: TxOptionsType): BaseTransaction<TxDataType, TxOptionsType>
  fromValuesArray(values: Buffer[], opts?: TxOptionsType): BaseTransaction<TxDataType, TxOptionsType>
}