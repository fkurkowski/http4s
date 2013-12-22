package org.http4s
package parserold

import org.parboiled.scala._
import org.parboiled.common.Base64
import BasicRules._

private[parserold] trait AuthorizationHeader {
  this: Parser with ProtocolParameterRules with AdditionalRules =>

  def AUTHORIZATION = rule {
    CredentialDef ~ EOI ~~> (Header.Authorization(_))
  }

  def CredentialDef = rule {
    BasicCredentialDef | OAuth2BearerTokenDef | GenericHttpCredentialsDef
  }

  def BasicCredentialDef = rule {
    "Basic" ~ BasicCookie ~> (BasicCredentials(_))
  }

  def BasicCookie = rule {
    oneOrMore(anyOf(Base64.rfc2045.getAlphabet)) ~ optional("==" | ch('='))
  }

  def OAuth2BearerTokenDef = rule {
    "Bearer" ~ Token ~~> (OAuth2BearerToken(_))
  }

  def GenericHttpCredentialsDef = rule {
    AuthScheme ~ CredentialParams ~~> { (scheme, params) => GenericCredentials(org.http4s.AuthScheme.getOrCreate(scheme), params) }
  }

  def CredentialParams = rule (
      oneOrMore(AuthParam, separator = ListSep) ~~> (_.toMap)
    | (Token | QuotedString) ~~> (param => Map("" -> param))
    | push(Map.empty[String, String])
  )

}