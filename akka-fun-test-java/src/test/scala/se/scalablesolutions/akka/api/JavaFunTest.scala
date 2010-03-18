package se.scalablesolutions.akka.api

import org.junit._
import runner._
import runners._
import Suite.SuiteClasses

@RunWith(classOf[Suite])
@SuiteClasses(Array(
	classOf[ActiveObjectGuiceConfiguratorTest],
//	classOf[InMemNestedStateTest],
//	classOf[InMemoryStateTest],
//	classOf[PersistentNestedStateTest],
//	classOf[PersistentStateTest],
	classOf[ProtobufSerializationTest],
//	classOf[RemoteInMemoryStateTest],
//	classOf[RemotePersistentStateTest],
	classOf[RestTest]))
class JavaFunTest extends com.novocode.junit.TestMarker {}