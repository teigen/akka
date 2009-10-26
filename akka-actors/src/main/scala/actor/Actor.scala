/**
 * Copyright (C) 2009 Scalable Solutions.
 */

package se.scalablesolutions.akka.actor

import java.net.InetSocketAddress
import java.util.HashSet

import se.scalablesolutions.akka.Config._
import se.scalablesolutions.akka.dispatch._
import se.scalablesolutions.akka.config.ScalaConfig._
import se.scalablesolutions.akka.stm.Transaction._
import se.scalablesolutions.akka.stm.TransactionManagement._
import se.scalablesolutions.akka.stm.{StmException, TransactionManagement}
import se.scalablesolutions.akka.nio.protobuf.RemoteProtocol.RemoteRequest
import se.scalablesolutions.akka.nio.{RemoteProtocolBuilder, RemoteClient, RemoteRequestIdFactory}
import se.scalablesolutions.akka.serialization.Serializer
import se.scalablesolutions.akka.util.Helpers.ReadWriteLock
import se.scalablesolutions.akka.util.Logging

import org.codehaus.aspectwerkz.joinpoint.{MethodRtti, JoinPoint}

import org.multiverse.utils.ThreadLocalTransaction._

sealed abstract class LifecycleMessage
case class Init(config: AnyRef) extends LifecycleMessage
//case object TransactionalInit extends LifecycleMessage
case class HotSwap(code: Option[PartialFunction[Any, Unit]]) extends LifecycleMessage
case class Restart(reason: AnyRef) extends LifecycleMessage
case class Exit(dead: Actor, killer: Throwable) extends LifecycleMessage

sealed abstract class DispatcherType
object DispatcherType {
  case object EventBasedThreadPooledProxyInvokingDispatcher extends DispatcherType
  case object EventBasedSingleThreadDispatcher extends DispatcherType
  case object EventBasedThreadPoolDispatcher extends DispatcherType
  case object ThreadBasedDispatcher extends DispatcherType
}

/**
 * @author <a href="http://jonasboner.com">Jonas Bon&#233;r</a>
 */
class ActorMessageInvoker(val actor: Actor) extends MessageInvoker {
  def invoke(handle: MessageInvocation) = actor.invoke(handle)
}

/**
 * @author <a href="http://jonasboner.com">Jonas Bon&#233;r</a>
 */
object Actor {
  val TIMEOUT = config.getInt("akka.actor.timeout", 5000)
  val SERIALIZE_MESSAGES = config.getBool("akka.actor.serialize-messages", false)
}

/**
 * @author <a href="http://jonasboner.com">Jonas Bon&#233;r</a>
 */
trait Actor extends Logging with TransactionManagement {
  ActorRegistry.register(this)
  
  @volatile private[this] var isRunning: Boolean = false
  private[this] val remoteFlagLock = new ReadWriteLock
  private[this] val transactionalFlagLock = new ReadWriteLock

  private var hotswap: Option[PartialFunction[Any, Unit]] = None
  private var config: Option[AnyRef] = None
 
  @volatile protected[this] var isTransactionRequiresNew = false
  @volatile protected[this] var remoteAddress: Option[InetSocketAddress] = None
  @volatile protected[akka] var supervisor: Option[Actor] = None
 
  protected[akka] var mailbox: MessageQueue = _
  protected[this] var senderFuture: Option[CompletableFutureResult] = None
  protected[this] val linkedActors = new HashSet[Actor]
  protected[actor] var lifeCycleConfig: Option[LifeCycle] = None

  val name = this.getClass.getName

  // ====================================
  // ==== USER CALLBACKS TO OVERRIDE ====
  // ====================================

  /**
   * User overridable callback/setting.
   *
   * Defines the default timeout for '!!' invocations, e.g. the timeout for the future returned by the call to '!!'.
   */
  @volatile var timeout: Long = Actor.TIMEOUT

  /**
   * User overridable callback/setting.
   *
   * User can (and is encouraged to) override the default configuration so it fits the specific use-case that the actor is used for.
   * <p/>
   * It is beneficial to have actors share the same dispatcher, easily +100 actors can share the same.
   * <br/>
   * But if you are running many many actors then it can be a good idea to have split them up in terms of dispatcher sharing.
   * <br/>
   * Default is that all actors that are created and spawned from within this actor is sharing the same dispatcher as its creator.
   * <pre>
   *   dispatcher = Dispatchers.newEventBasedThreadPoolDispatcher
   *     .withNewThreadPoolWithBoundedBlockingQueue(100)
   *     .setCorePoolSize(16)
   *     .setMaxPoolSize(128)
   *     .setKeepAliveTimeInMillis(60000)
   *     .setRejectionPolicy(new CallerRunsPolicy)
   *     .buildThreadPool
   * </pre>
   */
  protected[akka] var messageDispatcher: MessageDispatcher = {
    val dispatcher = Dispatchers.newEventBasedThreadPoolDispatcher(getClass.getName)
    mailbox = dispatcher.messageQueue
    dispatcher.registerHandler(this, new ActorMessageInvoker(this))
    dispatcher
  }

  /**
   * User overridable callback/setting.
   *
   * Identifier for actor, does not have to be a unique one. Simply the one used in logging etc.
   */
  protected[this] var id: String = this.getClass.toString

  /**
   * User overridable callback/setting.
   *
   * Set trapExit to true if actor should be able to trap linked actors exit messages.
   */
  protected[this] var trapExit: Boolean = false

  /**
   * User overridable callback/setting.
   *
   * If 'trapExit' is set for the actor to act as supervisor, then a faultHandler must be defined.
   * Can be one of:
   * <pre/>
   *  AllForOneStrategy(maxNrOfRetries: Int, withinTimeRange: Int)
   *
   *  OneForOneStrategy(maxNrOfRetries: Int, withinTimeRange: Int)
   * </pre>
   */
  protected var faultHandler: Option[FaultHandlingStrategy] = None

  /**
   * User overridable callback/setting.
   *
   * Partial function implementing the server logic.
   * To be implemented by subclassing server.
   * <p/>
   * Example code:
   * <pre>
   *   def receive: PartialFunction[Any, Unit] = {
   *     case Ping =>
   *       println("got a ping")
   *       reply("pong")
   *
   *     case OneWay =>
   *       println("got a oneway")
   *
   *     case _ =>
   *       println("unknown message, ignoring")
   *   }
   * </pre>
   */
  protected def receive: PartialFunction[Any, Unit]

  /**
   * User overridable callback/setting.
   *
   * Optional callback method that is called during initialization.
   * To be implemented by subclassing actor.
   */
  protected def init(config: AnyRef) = {}

  /**
   * User overridable callback/setting.
   *
   * Mandatory callback method that is called during restart and reinitialization after a server crash.
   * To be implemented by subclassing actor.
   */
  protected def preRestart(reason: AnyRef, config: Option[AnyRef]) = {}

  /**
   * User overridable callback/setting.
   *
   * Mandatory callback method that is called during restart and reinitialization after a server crash.
   * To be implemented by subclassing actor.
   */
  protected def postRestart(reason: AnyRef, config: Option[AnyRef]) = {}

  /**
   * User overridable callback/setting.
   *
   * Optional callback method that is called during termination.
   * To be implemented by subclassing actor.
   */
  protected def initTransactionalState() = {}

  /**
   * User overridable callback/setting.
   *
   * Optional callback method that is called during termination.
   * To be implemented by subclassing actor.
   */
  protected def shutdown {}

  // =============
  // ==== API ====
  // =============

  /**
   * Starts up the actor and its message queue.
   */
  def start = synchronized  {
    if (!isRunning) {
      messageDispatcher.start
      isRunning = true
      //if (isTransactional) this !! TransactionalInit
    }
    log.info("[%s] has started", toString)
  }

  /**
   * Stops the actor and its message queue.
   */
  def stop = synchronized {
    if (isRunning) {
      dispatcher.unregisterHandler(this)
      if (dispatcher.isInstanceOf[ThreadBasedDispatcher]) dispatcher.shutdown
      // FIXME: Need to do reference count to know if EventBasedThreadPoolDispatcher and EventBasedSingleThreadDispatcher can be shut down
      isRunning = false
      shutdown
    } else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")
  }

  /**
   * Sends a one-way asynchronous message. E.g. fire-and-forget semantics.
   */
  def !(message: AnyRef) =
    if (isRunning) postMessageToMailbox(message)
    else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")

  /**
   * Sends a message asynchronously and waits on a future for a reply message.
   * <p/>
   * It waits on the reply either until it receives it (in the form of <code>Some(replyMessage)</code>)
   * or until the timeout expires (which will return None). E.g. send-and-receive-eventually semantics.
   * <p/>
   * <b>NOTE:</b>
   * If you are sending messages using <code>!!</code> then you <b>have to</b> use <code>reply(..)</code>
   * to send a reply message to the original sender. If not then the sender will block until the timeout expires.
   */
  def !![T](message: AnyRef, timeout: Long): Option[T] = if (isRunning) {
    val future = postMessageToMailboxAndCreateFutureResultWithTimeout(message, timeout)
    val isActiveObject = message.isInstanceOf[Invocation]
    if (isActiveObject && message.asInstanceOf[Invocation].isVoid) future.completeWithResult(None)
    try {
      future.await
    } catch {
      case e: FutureTimeoutException =>
        if (isActiveObject) throw e
        else None
    }
    getResultOrThrowException(future)
  } else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")
  
  /**
   * Sends a message asynchronously and waits on a future for a reply message.
   * <p/>
   * It waits on the reply either until it receives it (in the form of <code>Some(replyMessage)</code>)
   * or until the timeout expires (which will return None). E.g. send-and-receive-eventually semantics.
   * <p/>
   * <b>NOTE:</b>
   * If you are sending messages using <code>!!</code> then you <b>have to</b> use <code>reply(..)</code>
   * to send a reply message to the original sender. If not then the sender will block until the timeout expires.
   */
  def !![T](message: AnyRef): Option[T] = !![T](message, timeout)

  /**
   * Sends a message asynchronously, but waits on a future indefinitely. E.g. emulates a synchronous call.
   * <p/>
   * <b>NOTE:</b>
   * Should be used with care (almost never), since very dangerous (will block a thread indefinitely if no reply).
   */
  def !?[T](message: AnyRef): T = if (isRunning) {
    val future = postMessageToMailboxAndCreateFutureResultWithTimeout(message, 0)
    future.awaitBlocking
    getResultOrThrowException(future).get
  } else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")

  /**
   * Use <code>reply(..)</code> to reply with a message to the original sender of the message currently
   * being processed.
   * <p/>
   * <b>NOTE:</b>
   * Does only work together with the actor <code>!!</code> method and/or active objects not annotated
   * with <code>@oneway</code>.
   */
  protected[this] def reply(message: AnyRef) = senderFuture match {
    case None => throw new IllegalStateException(
      "\n\tNo sender in scope, can't reply. " +
      "\n\tHave you used the '!' message send or the '@oneway' active object annotation? " +
      "\n\tIf so, switch to '!!' (or remove '@oneway') which passes on an implicit future that will be bound by the argument passed to 'reply'." )
    case Some(future) => future.completeWithResult(message)
  }

  def dispatcher = messageDispatcher

  /**
   * Sets the dispatcher for this actor. Needs to be invoked before the actor is started.
   */
  def dispatcher_=(dispatcher: MessageDispatcher): Unit = synchronized {
    if (!isRunning) {
      messageDispatcher = dispatcher
      mailbox = messageDispatcher.messageQueue
      messageDispatcher.registerHandler(this, new ActorMessageInvoker(this))
    } else throw new IllegalArgumentException("Can not swap dispatcher for " + toString + " after it has been started")
  }
  
  /**
   * Invoking 'makeRemote' means that an actor will be moved to and invoked on a remote host.
   */
  def makeRemote(hostname: String, port: Int): Unit = remoteFlagLock.withWriteLock {
    makeRemote(new InetSocketAddress(hostname, port))
  }

  /**
   * Invoking 'makeRemote' means that an actor will be moved to and invoked on a remote host.
   */
  def makeRemote(address: InetSocketAddress): Unit = remoteFlagLock.withWriteLock {
    remoteAddress = Some(address)
  }

  /**
   * Invoking 'makeTransactionRequired' means that the actor will **start** a new transaction if non exists.
   * However, it will always participate in an existing transaction.
   * If transactionality want to be completely turned off then do it by invoking:
   * <pre/>
   *  TransactionManagement.disableTransactions
   * </pre>
   */
  def makeTransactionRequired = synchronized {
    if (isRunning) throw new IllegalArgumentException("Can not make actor transaction required after it has been started")
    else isTransactionRequiresNew = true
  }

  /**
   * Links an other actor to this actor. Links are unidirectional and means that a the linking actor will receive a notification nif the linked actor has crashed.
   * If the 'trapExit' flag has been set then it will 'trap' the failure and automatically restart the linked actors according to the restart strategy defined by the 'faultHandler'.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def link(actor: Actor) = {
    if (isRunning) {
      linkedActors.add(actor)
      if (actor.supervisor.isDefined) throw new IllegalStateException("Actor can only have one supervisor [" + actor + "], e.g. link(actor) fails")
      actor.supervisor = Some(this)
      log.debug("Linking actor [%s] to actor [%s]", actor, this)
    } else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")
  }

  /**
   * Unlink the actor.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def unlink(actor: Actor) = {
    if (isRunning) {
      if (!linkedActors.contains(actor)) throw new IllegalStateException("Actor [" + actor + "] is not a linked actor, can't unlink")
      linkedActors.remove(actor)
      actor.supervisor = None
      log.debug("Unlinking actor [%s] from actor [%s]", actor, this)
    } else throw new IllegalStateException("Actor has not been started, you need to invoke 'actor.start' before using it")
  }

  /**
   * Atomically start and link an actor.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def startLink(actor: Actor) = {
    actor.start
    link(actor)
  }

  /**
   * Atomically start, link and make an actor remote.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def startLinkRemote(actor: Actor, hostname: String, port: Int) = {
    actor.makeRemote(hostname, port)
    actor.start
    link(actor)
  }

  /**
   * Atomically create (from actor class) and start an actor.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def spawn[T <: Actor](actorClass: Class[T]): T = {
    val actor = actorClass.newInstance.asInstanceOf[T]
    if (!dispatcher.isInstanceOf[ThreadBasedDispatcher]) {
      actor.dispatcher = dispatcher
      actor.mailbox = mailbox
    }
    actor.start
    actor
  }

  /**
   * Atomically create (from actor class), start and make an actor remote.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def spawnRemote[T <: Actor](actorClass: Class[T], hostname: String, port: Int): T = {
    val actor = actorClass.newInstance.asInstanceOf[T]
    actor.makeRemote(hostname, port)
    if (!dispatcher.isInstanceOf[ThreadBasedDispatcher]) {
      actor.dispatcher = dispatcher
      actor.mailbox = mailbox
    }
    actor.start
    actor
  }

  /**
   * Atomically create (from actor class), start and link an actor.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def spawnLink[T <: Actor](actorClass: Class[T]): T = {
    val actor = spawn[T](actorClass)
    link(actor)
    actor
  }

  /**
   * Atomically create (from actor class), start, link and make an actor remote.
   * <p/>
   * To be invoked from within the actor itself.
   */
  protected[this] def spawnLinkRemote[T <: Actor](actorClass: Class[T], hostname: String, port: Int): T = {
    val actor = spawn[T](actorClass)
    actor.makeRemote(hostname, port)
    link(actor)
    actor
  }

  // ================================
  // ==== IMPLEMENTATION DETAILS ====
  // ================================

  private def postMessageToMailbox(message: AnyRef): Unit = remoteFlagLock.withReadLock { // the price you pay for being able to make an actor remote at runtime
    if (remoteAddress.isDefined) {
      val requestBuilder = RemoteRequest.newBuilder
        .setId(RemoteRequestIdFactory.nextId)
        .setTarget(this.getClass.getName)
        .setTimeout(timeout)
        .setIsActor(true)
        .setIsOneWay(true)
        .setIsEscaped(false)
      val id = registerSupervisorAsRemoteActor
      if (id.isDefined) requestBuilder.setSupervisorUuid(id.get)
      RemoteProtocolBuilder.setMessage(message, requestBuilder)
      RemoteClient.clientFor(remoteAddress.get).send(requestBuilder.build)
    } else {
      val handle = new MessageInvocation(this, message, None, currentTransaction.get)
      handle.send
    }
  }

  private def postMessageToMailboxAndCreateFutureResultWithTimeout(message: AnyRef, timeout: Long): CompletableFutureResult = remoteFlagLock.withReadLock { // the price you pay for being able to make an actor remote at runtime
    if (remoteAddress.isDefined) {
      val requestBuilder = RemoteRequest.newBuilder                                                                                                
        .setId(RemoteRequestIdFactory.nextId)
        .setTarget(this.getClass.getName)
        .setTimeout(timeout)
        .setIsActor(true)
        .setIsOneWay(false)
        .setIsEscaped(false)
      RemoteProtocolBuilder.setMessage(message, requestBuilder)
      val id = registerSupervisorAsRemoteActor
      if (id.isDefined) requestBuilder.setSupervisorUuid(id.get)
      val future = RemoteClient.clientFor(remoteAddress.get).send(requestBuilder.build)
      if (future.isDefined) future.get
      else throw new IllegalStateException("Expected a future from remote call to actor " + toString)
    } else {
      val future = new DefaultCompletableFutureResult(timeout)
      val handle = new MessageInvocation(this, message, Some(future), currentTransaction.get)
      handle.send
      future
    }
  }

  /**
   * Callback for the dispatcher. E.g. single entry point to the user code and all protected[this] methods
   */
  private[akka] def invoke(messageHandle: MessageInvocation) = synchronized {
    if (TransactionManagement.isTransactionalityEnabled) transactionalDispatch(messageHandle)
    else dispatch(messageHandle)
  }

  private def dispatch[T](messageHandle: MessageInvocation) = {
    setTransaction(messageHandle.tx)

    val message = messageHandle.message //serializeMessage(messageHandle.message)
    val future = messageHandle.future
    try {
      senderFuture = future
      if (base.isDefinedAt(message)) base(message) // invoke user actor's receive partial function
      else throw new IllegalArgumentException("No handler matching message [" + message + "] in " + toString)
    } catch {
      case e =>
        // FIXME to fix supervisor restart of remote actor for oneway calls, inject a supervisor proxy that can send notification back to client
        if (supervisor.isDefined) supervisor.get ! Exit(this, e)
        if (future.isDefined) future.get.completeWithException(this, e)
        else e.printStackTrace
    } finally {
      clearTransaction
    }
  }

  private def transactionalDispatch[T](messageHandle: MessageInvocation) = {
    setTransaction(messageHandle.tx)
    
    val message = messageHandle.message //serializeMessage(messageHandle.message)
    val future = messageHandle.future

    def proceed = {
      try {
        incrementTransaction
        if (base.isDefinedAt(message)) base(message) // invoke user actor's receive partial function
        else throw new IllegalArgumentException("Actor " + toString + " could not process message [" + message + "] since no matching 'case' clause in its 'receive' method could be found")
      } finally {
        decrementTransaction
      }
    }
    
    try {
      senderFuture = future
      if (isTransactionRequiresNew && !isTransactionInScope) {
        if (senderFuture.isEmpty) throw new StmException(
          "\n\tCan't continue transaction in a one-way fire-forget message send" +
          "\n\tE.g. using Actor '!' method or Active Object 'void' method" +
          "\n\tPlease use the Actor '!!', '!?' methods or Active Object method with non-void return type")
        atomic {
          proceed
        }
      } else proceed
    } catch {
      case e =>
        e.printStackTrace

        if (future.isDefined) future.get.completeWithException(this, e)
        else e.printStackTrace

        clearTransaction // need to clear currentTransaction before call to supervisor

        // FIXME to fix supervisor restart of remote actor for oneway calls, inject a supervisor proxy that can send notification back to client
        if (supervisor.isDefined) supervisor.get ! Exit(this, e)
    } finally {
      clearTransaction
    }
  }

  private def getResultOrThrowException[T](future: FutureResult): Option[T] =
    if (future.exception.isDefined) throw future.exception.get._2
    else future.result.asInstanceOf[Option[T]]

  private def base: PartialFunction[Any, Unit] = lifeCycle orElse (hotswap getOrElse receive)

  private val lifeCycle: PartialFunction[Any, Unit] = {
    case Init(config) =>       init(config)
    case HotSwap(code) =>      hotswap = code
    case Restart(reason) =>    restart(reason)
    case Exit(dead, reason) => handleTrapExit(dead, reason)
//    case TransactionalInit =>  initTransactionalState
  }

  private[this] def handleTrapExit(dead: Actor, reason: Throwable): Unit = {
    if (trapExit) {
      if (faultHandler.isDefined) {
        faultHandler.get match {
          // FIXME: implement support for maxNrOfRetries and withinTimeRange in RestartStrategy
          case AllForOneStrategy(maxNrOfRetries, withinTimeRange) => restartLinkedActors(reason)
          case OneForOneStrategy(maxNrOfRetries, withinTimeRange) => dead.restart(reason)
        }
      } else throw new IllegalStateException("No 'faultHandler' defined for actor with the 'trapExit' flag set to true - can't proceed " + toString)
    } else {
      if (supervisor.isDefined) supervisor.get ! Exit(dead, reason) // if 'trapExit' is not defined then pass the Exit on
    }
  }

  private[this] def restartLinkedActors(reason: AnyRef) =
    linkedActors.toArray.toList.asInstanceOf[List[Actor]].foreach(_.restart(reason))

  private[Actor] def restart(reason: AnyRef) = synchronized {
    lifeCycleConfig match {
      case None => throw new IllegalStateException("Actor [" + id + "] does not have a life-cycle defined.")

      // FIXME implement support for shutdown time
      case Some(LifeCycle(scope, shutdownTime, _)) => {
        scope match {
          case Permanent => {
            preRestart(reason, config)
            log.info("Restarting actor [%s] configured as PERMANENT.", id)
            postRestart(reason, config)
          }

          case Temporary =>
          // FIXME handle temporary actors correctly - restart if exited normally
//            if (reason == 'normal) {
//              log.debug("Restarting actor [%s] configured as TEMPORARY (since exited naturally).", id)
//              scheduleRestart
//            } else
            log.info("Actor [%s] configured as TEMPORARY will not be restarted (received unnatural exit message).", id)

          case Transient =>
            log.info("Actor [%s] configured as TRANSIENT will not be restarted.", id)
        }
      }
    }
  }

  private[akka] def registerSupervisorAsRemoteActor: Option[String] = synchronized {
    if (supervisor.isDefined) {
      RemoteClient.clientFor(remoteAddress.get).registerSupervisorForActor(this)
      Some(supervisor.get.uuid)
    } else None
  }


  private[akka] def swapDispatcher(disp: MessageDispatcher) = synchronized {
    messageDispatcher = disp
    mailbox = messageDispatcher.messageQueue
    messageDispatcher.registerHandler(this, new ActorMessageInvoker(this))
  }

  private def serializeMessage(message: AnyRef): AnyRef = if (Actor.SERIALIZE_MESSAGES) {
    if (!message.isInstanceOf[String] &&
      !message.isInstanceOf[Byte] &&
      !message.isInstanceOf[Int] &&
      !message.isInstanceOf[Long] &&
      !message.isInstanceOf[Float] &&
      !message.isInstanceOf[Double] &&
      !message.isInstanceOf[Boolean] &&
      !message.isInstanceOf[Char] &&
      !message.isInstanceOf[Tuple2[_,_]] &&
      !message.isInstanceOf[Tuple3[_,_,_]] &&
      !message.isInstanceOf[Tuple4[_,_,_,_]] &&
      !message.isInstanceOf[Tuple5[_,_,_,_,_]] &&
      !message.isInstanceOf[Tuple6[_,_,_,_,_,_]] &&
      !message.isInstanceOf[Tuple7[_,_,_,_,_,_,_]] &&
      !message.isInstanceOf[Tuple8[_,_,_,_,_,_,_,_]] &&
      !message.getClass.isArray &&
      !message.isInstanceOf[List[_]] &&
      !message.isInstanceOf[scala.collection.immutable.Map[_,_]] &&
      !message.isInstanceOf[scala.collection.immutable.Set[_]] &&
      !message.isInstanceOf[scala.collection.immutable.Tree[_,_]] &&
      !message.getClass.isAnnotationPresent(Annotations.immutable)) {
      Serializer.Java.deepClone(message)
    } else message
  } else message

  override def toString(): String = "Actor[" + uuid + ":" + id + "]"
}
