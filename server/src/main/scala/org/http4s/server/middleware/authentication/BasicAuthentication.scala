package org.http4s
package server
package middleware
package authentication

import org.http4s.headers.Authorization
import scalaz._, Scalaz._
import scalaz.concurrent.Task

/**
 * Provides Basic Authentication from RFC 2617.
 * @param realm The realm used for authentication purposes.
 * @param store A partial function mapping (realm, user) to the
 *              appropriate password.
 */
class BasicAuthentication(realm: String, store: AuthenticationStore) extends Authentication {

  protected def getChallenge(req: Request) = checkAuth(req).map {
    case Some(user) => \/-(addUserRealmAttributes(req, user, realm))
    case None       => -\/(Challenge("Basic", realm, Map.empty))
  }

  private def checkAuth(req: Request): Task[Option[String]] = {
    req.headers.get(Authorization)
      .filter(_.credentials.authScheme == AuthScheme.Basic)
      .traverseM {
        case Authorization(BasicCredentials(user, password)) =>
          store(realm, user) map {
            case Some(srvPassword) if password == srvPassword => user.some
            case _ => none
          }
      }
  }
}
