/**
 * Copyright (C) 2009 Scalable Solutions.
 */

package sample.secure

import se.scalablesolutions.akka.kernel.state.{TransactionalState, CassandraStorageConfig}
import se.scalablesolutions.akka.kernel.actor.{SupervisorFactory, Actor}
import se.scalablesolutions.akka.kernel.config.ScalaConfig._
import se.scalablesolutions.akka.kernel.util.Logging
import se.scalablesolutions.akka.kernel.rest.{DigestAuthenticationActor, UserInfo}
import _root_.javax.annotation.security.{DenyAll,PermitAll,RolesAllowed}
import javax.ws.rs.{GET, POST, Path, Produces, Consumes}

class Boot {
  object factory extends SupervisorFactory {
    override def getSupervisorConfig: SupervisorConfig = {
      SupervisorConfig(
        RestartStrategy(OneForOne, 3, 100),
        Supervise(
          new SimpleAuthenticationService,
          LifeCycle(Permanent, 100)) ::
        Supervise(
          new SecureService,
          LifeCycle(Permanent, 100)):: Nil)
    }
  }

  val supervisor = factory.newSupervisor
  supervisor.startSupervisor
}

class SimpleAuthenticationService extends DigestAuthenticationActor
{
    //makeTransactionRequired
    //override def mkNonceMap = TransactionalState.newPersistentMap(CassandraStorageConfig()).asInstanceOf[scala.collection.mutable.Map[String,Long]]
    override def mkNonceMap = new scala.collection.mutable.HashMap[String,Long]
    override def realm = "test"
    override def userInfo(username : String) : Option[UserInfo] = Some(UserInfo(username,"bar","ninja" :: "chef" :: Nil))
}

@Path("/securecount")
class SecureService extends Actor with Logging {
  makeTransactionRequired

    log.info("Creating SecureService")

  case object Tick
  private val KEY = "COUNTER";
  private var hasStartedTicking = false;
  private val storage = TransactionalState.newPersistentMap(CassandraStorageConfig())

  @GET
  @Produces(Array("text/html"))
  @RolesAllowed(Array("chef"))
  def count = (this !! Tick).getOrElse(<error>Error in counter</error>)

  override def receive: PartialFunction[Any, Unit] = {
    case Tick => if (hasStartedTicking) {
      val counter = storage.get(KEY).get.asInstanceOf[Integer].intValue
      storage.put(KEY, new Integer(counter + 1))
      reply(<success>Tick:{counter + 1}</success>)
    } else {
      storage.put(KEY, new Integer(0))
      hasStartedTicking = true
      reply(<success>Tick: 0</success>)
    }
  }
}