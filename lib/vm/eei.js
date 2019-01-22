const utils = require('ethereumjs-util')
const BN = utils.BN
const exceptions = require('../exceptions.js')
const ERROR = exceptions.ERROR
const VmError = exceptions.VmError

module.exports = class EEI {
  constructor (runState) {
    this._runState = runState
  }

  /**
   * NOTE: This is not defined in EEI spec. Should find a
   * better alternative.
   */
  stop () {
    this._runState.stopped = true
  }

  describeLocation () {
    var hash = utils.keccak256(this._runState.code).toString('hex')
    var address = this._runState.address.toString('hex')
    var pc = this._runState.programCounter - 1
    return hash + '/' + address + ':' + pc
  }

  subGas (amount) {
    this._runState.gasLeft.isub(amount)
    if (this._runState.gasLeft.ltn(0)) {
      this._runState.gasLeft = new BN(0)
      this.trap(ERROR.OUT_OF_GAS)
    }
  }

  /**
   * Loads bytes from memory and returns them as a buffer. If an error occurs
   * a string is instead returned. The function also subtracts the amount of
   * gas need for memory expansion.
   * @method memLoad
   * @param {Object} runState
   * @param {BN} offset where to start reading from
   * @param {BN} length how far to read
   * @returns {Buffer|String}
   */
  memLoad (offset, length) {
    // check to see if we have enougth gas for the mem read
    this.subMemUsage(offset, length)

    // shortcut
    if (length.isZero()) {
      return Buffer.alloc(0)
    }

    // NOTE: in theory this could overflow, but unlikely due to OOG above
    offset = offset.toNumber()
    length = length.toNumber()

    var loaded = this._runState.memory.slice(offset, offset + length)
    // fill the remaining lenth with zeros
    for (var i = loaded.length; i < length; i++) {
      loaded[i] = 0
    }
    return Buffer.from(loaded)
  }

  /**
   * Subtracts the amount needed for memory usage from `runState.gasLeft`
   * @method subMemUsage
   * @param {Object} runState
   * @param {BN} offset
   * @param {BN} length
   * @returns {String}
   */
  subMemUsage (offset, length) {
    // YP (225): access with zero length will not extend the memory
    if (length.isZero()) return

    const newMemoryWordCount = offset.add(length).divCeil(new BN(32))
    if (newMemoryWordCount.lte(this._runState.memoryWordCount)) return

    const words = newMemoryWordCount
    const fee = new BN(this._runState._common.param('gasPrices', 'memory'))
    const quadCoeff = new BN(this._runState._common.param('gasPrices', 'quadCoeffDiv'))
    // words * 3 + words ^2 / 512
    const cost = words.mul(fee).add(words.mul(words).div(quadCoeff))

    if (cost.gt(this._runState.highestMemCost)) {
      this.subGas(cost.sub(this._runState.highestMemCost))
      this._runState.highestMemCost = cost
    }

    this._runState.memoryWordCount = newMemoryWordCount
  }

  trap (err) {
    throw new VmError(err)
  }

  /**
   * Stores bytes to memory. If an error occurs a string is instead returned.
   * The function also subtracts the amount of gas need for memory expansion.
   * @method memStore
   * @param {Object} runState
   * @param {BN} offset where to start reading from
   * @param {Buffer} val
   * @param {BN} valOffset
   * @param {BN} length how far to read
   * @param {Boolean} skipSubMem
   * @returns {Buffer|String}
   */
  memStore (offset, val, valOffset, length, skipSubMem) {
    if (skipSubMem !== false) {
      this.subMemUsage(offset, length)
    }

    // shortcut
    if (length.isZero()) {
      return
    }

    // NOTE: in theory this could overflow, but unlikely due to OOG above
    offset = offset.toNumber()
    length = length.toNumber()

    var safeLen = 0
    if (valOffset.addn(length).gtn(val.length)) {
      if (valOffset.gten(val.length)) {
        safeLen = 0
      } else {
        valOffset = valOffset.toNumber()
        safeLen = val.length - valOffset
      }
    } else {
      valOffset = valOffset.toNumber()
      safeLen = val.length
    }

    let i = 0
    if (safeLen > 0) {
      safeLen = safeLen > length ? length : safeLen
      for (; i < safeLen; i++) {
        this._runState.memory[offset + i] = val[valOffset + i]
      }
    }

    /*
    pad the remaining length with zeros IF AND ONLY IF a value was stored
    (even if value offset > value length, strange spec...)
    */
    if (val.length > 0 && i < length) {
      for (; i < length; i++) {
        this._runState.memory[offset + i] = 0
      }
    }
  }

  // checks if a jump is valid given a destination
  jumpIsValid (dest) {
    return this._runState.validJumps.indexOf(dest) !== -1
  }

  // checks to see if we have enough gas left for the memory reads and writes
  // required by the CALLs
  checkCallMemCost (callOptions, localOpts) {
    // calculates the gas need for saving the output in memory
    this.subMemUsage(localOpts.outOffset, localOpts.outLength)

    if (!callOptions.gasLimit) {
      callOptions.gasLimit = new BN(this._runState.gasLeft)
    }
  }

  checkOutOfGas (callOptions) {
    const gasAllowed = this._runState.gasLeft.sub(this._runState.gasLeft.divn(64))
    if (callOptions.gasLimit.gt(gasAllowed)) {
      callOptions.gasLimit = gasAllowed
    }
  }

  // sets up and calls runCall
  makeCall (callOptions, localOpts, cb) {
    var selfdestruct = Object.assign({}, this._runState.selfdestruct)
    callOptions.caller = callOptions.caller || this._runState.address
    callOptions.origin = this._runState.origin
    callOptions.gasPrice = this._runState.gasPrice
    callOptions.block = this._runState.block
    callOptions.static = callOptions.static || false
    callOptions.selfdestruct = selfdestruct
    callOptions.storageReader = this._runState.storageReader

    // increment the runState.depth
    callOptions.depth = this._runState.depth + 1

    // empty the return data buffer
    this._runState.lastReturned = Buffer.alloc(0)

    // check if account has enough ether
    // Note: in the case of delegatecall, the value is persisted and doesn't need to be deducted again
    if (this._runState.depth >= this._runState._common.param('vm', 'stackLimit') || (callOptions.delegatecall !== true && new BN(this._runState.contract.balance).lt(callOptions.value))) {
      cb(null, new BN(0))
    } else {
      // if creating a new contract then increament the nonce
      if (!callOptions.to) {
        this._runState.contract.nonce = new BN(this._runState.contract.nonce).addn(1)
      }

      this._runState.stateManager.putAccount(this._runState.address, this._runState.contract, function (err) {
        if (err) return cb(err)
        this._runState._vm.runCall(callOptions, parseCallResults)
      })
    }

    function parseCallResults (err, results) {
      if (err) return cb(err)

      // concat the runState.logs
      if (results.vm.logs) {
        this._runState.logs = this._runState.logs.concat(results.vm.logs)
      }

      // add gasRefund
      if (results.vm.gasRefund) {
        this._runState.gasRefund = this._runState.gasRefund.add(results.vm.gasRefund)
      }

      // this should always be safe
      this._runState.gasLeft.isub(results.gasUsed)

      // save results to memory
      if (results.vm.return && (!results.vm.exceptionError || results.vm.exceptionError.error === ERROR.REVERT)) {
        this.memStore(localOpts.outOffset, results.vm.return, new BN(0), localOpts.outLength, false)

        if (results.vm.exceptionError && results.vm.exceptionError.error === ERROR.REVERT && this.isCreateOpCode(this._runState.opName)) {
          this._runState.lastReturned = results.vm.return
        }

        switch (this._runState.opName) {
          case 'CALL':
          case 'CALLCODE':
          case 'DELEGATECALL':
          case 'STATICCALL':
            this._runState.lastReturned = results.vm.return
            break
        }
      }

      if (!results.vm.exceptionError) {
        Object.assign(this._runState.selfdestruct, selfdestruct)
        // update stateRoot on current contract
        this._runState.stateManager.getAccount(this._runState.address, function (err, account) {
          if (err) return cb(err)

          this._runState.contract = account
          // push the created address to the stack
          if (results.createdAddress) {
            cb(null, new BN(results.createdAddress))
          } else {
            cb(null, new BN(results.vm.exception))
          }
        })
      } else {
        // creation failed so don't increment the nonce
        if (results.vm.createdAddress) {
          this._runState.contract.nonce = new BN(this._runState.contract.nonce).subn(1)
        }

        cb(null, new BN(results.vm.exception))
      }
    }
  }

  isCreateOpCode (opName) {
    return opName === 'CREATE' || opName === 'CREATE2'
  }

  getContractStorage (address, key, cb) {
    if (this._runState._common.gteHardfork('constantinople')) {
      this._runState.storageReader.getContractStorage(address, key, cb)
    } else {
      this._runState.stateManager.getContractStorage(address, key, cb)
    }
  }

  updateSstoreGas (found, value) {
    if (this._runState._common.gteHardfork('constantinople')) {
      var original = found.original
      var current = found.current
      if (current.equals(value)) {
        // If current value equals new value (this is a no-op), 200 gas is deducted.
        this.subGas(this._runState, new BN(this._runState._common.param('gasPrices', 'netSstoreNoopGas')))
        return
      }
      // If current value does not equal new value
      if (original.equals(current)) {
        // If original value equals current value (this storage slot has not been changed by the current execution context)
        if (original.length === 0) {
          // If original value is 0, 20000 gas is deducted.
          return this.subGas(new BN(this._runState._common.param('gasPrices', 'netSstoreInitGas')))
        }
        if (value.length === 0) {
          // If new value is 0, add 15000 gas to refund counter.
          this._runState.gasRefund = this._runState.gasRefund.addn(this._runState._common.param('gasPrices', 'netSstoreClearRefund'))
        }
        // Otherwise, 5000 gas is deducted.
        return this.subGas(new BN(this._runState._common.param('gasPrices', 'netSstoreCleanGas')))
      }
      // If original value does not equal current value (this storage slot is dirty), 200 gas is deducted. Apply both of the following clauses.
      if (original.length !== 0) {
        // If original value is not 0
        if (current.length === 0) {
          // If current value is 0 (also means that new value is not 0), remove 15000 gas from refund counter. We can prove that refund counter will never go below 0.
          this._runState.gasRefund = this._runState.gasRefund.subn(this._runState._common.param('gasPrices', 'netSstoreClearRefund'))
        } else if (value.length === 0) {
          // If new value is 0 (also means that current value is not 0), add 15000 gas to refund counter.
          this._runState.gasRefund = this._runState.gasRefund.addn(this._runState._common.param('gasPrices', 'netSstoreClearRefund'))
        }
      }
      if (original.equals(value)) {
        // If original value equals new value (this storage slot is reset)
        if (original.length === 0) {
          // If original value is 0, add 19800 gas to refund counter.
          this._runState.gasRefund = this._runState.gasRefund.addn(this._runState._common.param('gasPrices', 'netSstoreResetClearRefund'))
        } else {
          // Otherwise, add 4800 gas to refund counter.
          this._runState.gasRefund = this._runState.gasRefund.addn(this._runState._common.param('gasPrices', 'netSstoreResetRefund'))
        }
      }
      return this.subGas(new BN(this._runState._common.param('gasPrices', 'netSstoreDirtyGas')))
    } else {
      if (value.length === 0 && !found.length) {
        this.subGas(new BN(this._runState._common.param('gasPrices', 'sstoreReset')))
      } else if (value.length === 0 && found.length) {
        this.subGas(new BN(this._runState._common.param('gasPrices', 'sstoreReset')))
        this._runState.gasRefund.iaddn(this._runState._common.param('gasPrices', 'sstoreRefund'))
      } else if (value.length !== 0 && !found.length) {
        this.subGas(new BN(this._runState._common.param('gasPrices', 'sstoreSet')))
      } else if (value.length !== 0 && found.length) {
        this.subGas(new BN(this._runState._common.param('gasPrices', 'sstoreReset')))
      }
    }
  }
}