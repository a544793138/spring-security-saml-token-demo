# spring-security-saml-token-demo

结合 spring security，采用 SAML token 的方式进行用户的认证，与正常的 SAML 不一样，只是将 SAML 作为 token 验证的一个例子，如 JWT token 类似。
demo 中会要求所有请求都需要带有 SAML token（SAML 响应或 SAML 断言），会对 SAML token 进行 SAML 规范的验证（demo 只对 SAML 断言进行验证，包括 SAML 响应中的断言。目前验证了摘要、签名、有效期和 Issuer）

## demo 的设定

- 要求所有的请求均需要在 HTTP header 中带有 `Authorization` 属性（类型为 `Bearer Token`），
且其值为 SAML token（token 必须是紧凑的，不能存在换行或多余的空格，标签中属性之间的除外，不过 demo 中也尝试对不紧凑的 XML 内容进行紧凑化，但不保证一定没有问题，如果有找到第三方库可用的 API 可以替换），否则报 401。
- 通过 token 验证后的用户角色为 `USER`。
- `/hello` 接口不需要角色即可访问。
- `/user/{id}` 接口需要 `USER` 角色才可以访问。
- `/admin/{id}` 接口需要 `ADMIN` 角色才可以访问