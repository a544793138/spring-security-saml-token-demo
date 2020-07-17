# spring-security-saml-token-demo
结合 spring security，采用 SAML token 的方式进行用户的认证，与正常的 SAML 不一样，只是将 SAML 作为 token 验证的一个例子，如 JWT token 类似。
demo 中也只是简单的对 token 进行验证，没有涉及 SAML 的规范。

## demo 的设定

- 要求所有的请求均需要在 HTTP header 中带有 `Authorization` 属性（类型为 `Bearer Token`），且其值为 `com:tjwoods:saml:token`，否则报 401。
- 通过 token 验证后的用户角色为 `USER`。
- `/hello` 接口不需要角色即可访问。
- `/user/{id}` 接口需要 `USER` 角色才可以访问。
- `/admin/{id}` 接口需要 `ADMIN` 角色才可以访问
