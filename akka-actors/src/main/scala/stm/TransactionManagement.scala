/**
 * Copyright (C) 2009 Scalable Solutions.
 */

package se.scalablesolutions.akka.stm

import java.util.concurrent.atomic.AtomicBoolean

import se.scalablesolutions.akka.util.Logging

import org.codehaus.aspectwerkz.proxy.Uuid

import scala.collection.mutable.HashSet

import org.multiverse.utils.ThreadLocalTransaction._

class StmException(msg: String) extends RuntimeException(msg)

class TransactionAwareWrapperException(val cause: Throwable, val tx: Option[Transaction]) extends RuntimeException(cause) {
  override def toString(): String = "TransactionAwareWrapperException[" + cause + ", " + tx + "]"
}

object TransactionManagement extends TransactionManagement {
  import se.scalablesolutions.akka.Config._
  // FIXME reenable 'akka.stm.restart-on-collision' when new STM is in place
  val RESTART_TRANSACTION_ON_COLLISION =   false //akka.Kernel.config.getBool("akka.stm.restart-on-collision", true)
  val TIME_WAITING_FOR_COMPLETION =        config.getInt("akka.stm.wait-for-completion", 1000)
  val NR_OF_TIMES_WAITING_FOR_COMPLETION = config.getInt("akka.stm.wait-nr-of-times", 3)
  val MAX_NR_OF_RETRIES =                  config.getInt("akka.stm.max-nr-of-retries", 100)
  val TRANSACTION_ENABLED =                new AtomicBoolean(config.getBool("akka.stm.service", false))

  def isTransactionalityEnabled = TRANSACTION_ENABLED.get
  def disableTransactions = TRANSACTION_ENABLED.set(false)

  private[akka] val currentTransaction: ThreadLocal[Option[Transaction]] = new ThreadLocal[Option[Transaction]]() {
    override protected def initialValue: Option[Transaction] = None
  }
}

trait TransactionManagement extends Logging {
  // FIXME is java.util.UUID better?
  var uuid = Uuid.newUuid.toString
  
  import TransactionManagement.currentTransaction
  private[akka] val activeTransactions = new HashSet[Transaction]

  private[akka] def createNewTransaction = currentTransaction.set(Some(new Transaction))

  private[akka] def setTransaction(transaction: Option[Transaction]) = if (transaction.isDefined) {
    val tx = transaction.get
    //log.debug("Setting transaction [%s]", transaction.get)
    currentTransaction.set(transaction)
    if (tx.transaction.isDefined) setThreadLocalTransaction(tx.transaction.get)
    else throw new IllegalStateException("No transaction defined")
  }

  private[akka] def clearTransaction = {
    //if (isTransactionInScope) log.debug("Clearing transaction [%s]", getTransactionInScope)
    currentTransaction.set(None)
    setThreadLocalTransaction(null)
  }

  private[akka] def getTransactionInScope = currentTransaction.get.get
  
  private[akka] def isTransactionInScope = currentTransaction.get.isDefined

  private[akka] def incrementTransaction =
    if (isTransactionInScope) getTransactionInScope.increment
    //else throw new IllegalStateException("No transaction in scope")

  private[akka] def decrementTransaction =
    if (isTransactionInScope) getTransactionInScope.decrement
    //else throw new IllegalStateException("No transaction in scope")
    
  private[akka] def removeTransactionIfTopLevel(tx: Transaction) = if (tx.isTopLevel) { activeTransactions -= tx }
}

