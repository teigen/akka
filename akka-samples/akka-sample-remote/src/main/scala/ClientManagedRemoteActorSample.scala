/**
 * Copyright (C) 2009-2011 Scalable Solutions AB <http://scalablesolutions.se>
 */

package sample.remote

import akka.actor.Actor._
import akka.util.Logging
import akka.actor. {ActorRegistry, Actor}
import Actor.remote

class RemoteHelloWorldActor extends Actor {
  def receive = {
    case "Hello" =>
      log.slf4j.info("Received 'Hello'")
      self.reply("World")
  }
}

object ClientManagedRemoteActorServer extends Logging {
  def run = {
    remote.start("localhost", 2552)
    log.slf4j.info("Remote node started")
  }

  def main(args: Array[String]) = run
}

object ClientManagedRemoteActorClient extends Logging {

  def run = {
    val actor = remote.actorOf[RemoteHelloWorldActor]("localhost",2552).start
    log.slf4j.info("Remote actor created, moved to the server")
    log.slf4j.info("Sending 'Hello' to remote actor")
    val result = actor !! "Hello"
    log.slf4j.info("Result from Remote Actor: '{}'", result.get)
  }

  def main(args: Array[String]) = run
}

