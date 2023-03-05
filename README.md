# Spring Authorization Server Practice
Spring Authorization Server 프레임워크는 OAuth 2.0 중 Authorization Server 부분을 쉽게 구현할 수 있게 해준다.
우선 OAuth 2.0에 대해 간략히 살펴보자. 

## OAuth 2.0
![](./resources/oauth2.png)

rfc6749 문서에 따르면 'OAuth 2.0 인가(인증) 프레임워크'라는 말로 OAuth 2.0을 풀이한다.
OAuth 2.0은 서드파티 앱이 특정 서비스의 제한이 걸린 자원에 접근하기 위해 리소스 오너(사용자)의 허락을 받아 자원에 접근을 하게되는 일련의 플로우를 제공한다.
구글, 페이스북 등 유수의 IT 기업들은 자신의 우수한 회원 체계, 여러 코어 서비스를 바탕으로 OAuth 2.0 서비스를 제공하고 있다.

rfc문서에서는 프레임워크라고 말하는데 알고리즘, 프로토콜 같은 조그만 범위를 넘어 일종의 체계화된 틀이며 이 틀에 맞춰 충실히 스펙을 구현하면 된다는 말로도 이해할 수 있다. 이어서 말하겠지만 OAuth 2.0의 구조는 단순한 편이 결코 아니다.

### Protocol Flow

![](./resources/oauth2-protocol-flow.png)

OAuth 2.0의 구성요소를 살펴보자.
* Client : Protected Resource에 접근하고 싶어하는 주체이며 웹앱, 모바일앱, 기타 프로그램 중 어떤 것도 될 수 있다.
* Resource Owner : Protected Resource에 대한 접근을 허용하는 주체이며 대부분의 경우 end-user, 즉 사용자를 의미한다.
* Authorization Server : Resource Owner를 인증하고 Access Token을 발급하는 서버.
* Resource Server : Access Token을 파라미터로 받아 검증하고 Protected Resource을 제공하는 서버.  

Protocol Flow를 간단히 살펴보면 아래와 같다.
* (A), (B), (C), (D) : 인증을 통한 Access Token 획득
* (E), (F) : Access Token을 이용한 Protected Resource을 이용

### Client Credentials Grant
OAuth 2.0 여러 인증 방식 중 Server to Server 구현에 해당하며 가장 간단한 **Client Credentials Grant**을 구현해보고자 한다.

![](./resources/client-credentials-grant.png)

이 방식은 Client와 Authorization Server 간 보안 환경(SSL) 등 신뢰할 수 있는 구간에서 활용할 수 있는 방식이다. Client는 Access Token을 얻은 다음 Resource Server에 접근하여 Protected Resource에 접근할 수 있다.

이 Protocol Flow가 동작하기 전에 Authorization Server에서 ClientId, ClientSecret을 생성한 다음 Client가 이를 갖고 있는 상황에서 진행해야 한다.  

## Authorization Server Practice
OAuth 2.0에 대해 여러 구현이 있지만 23년 3월 기준으로 최신 구현인 Spring Authorization Server 프레임워크를 이용하고자 한다.
이 프레임워크도 Spring Security의 SecurityFilterChain 기반으로 동작하므로 Spring Security에 대한 이해가 선행되어 있어야 한다.

![](./resources/spring-authorization-server-reference.png)
위 이미지는 공식 Reference 문서이다. Access Token을 발급하는 부분을 보고 싶으면 Protocol Endpoints -> OAuth2 Token Endpoint를 참조하면 된다.
해당 가이드에서는 AccessTokenRequestConverter, AuthenticationProvider, AccessTokenResponseHandler 등 SecurityFilterChain 구현체에 참여하는 다양한 요소들에 대해 커스터마이저를 제공하지만 커스터마이징을 할 필요는 거의 없을 것이다. 프레임워크가 rfc 문서에 적혀있는 OAuth 2.0 프레임워크의 스펙을 대부분 커버하므로 그대로 활용하면 될 뿐이다.

ClientId, ClientSecret 등 Client Authentication 동작에 필요한 저장소는 RegisteredClientRepository을 구현하면 되는데, In-Memory, Jdbc 구현체를 기본적으로 제공하며 [JPA 기반으로 작성된 예제](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/guides/how-to-jpa.html)도 충분히 제공하고 있다. JPA로 구현을 해봤었는데 이번에는 간단하게 In-Memory로 구현해보겠다.

### Security Configuration
[SecurityConfiguration](./src/main/kotlin/com/traeper/oauth2/authorization/configuration/SecurityConfiguration.kt) 파일을 보면 심플하게 구현된 SecurityFilterChain을 볼 수 있다. Reference가 워낙 잘 나와서 보고 따라 적으면 되는 수준이긴 하다. 👍  
Client Credentials Grant 방식에 Authorization Basic Header를 이용한 인증 방식을 지원하기 위해 RegisteredClientRepository의 구현체는 아래처럼 커스터마이징 했다. 참고로 Access Token, Refresh Token 등의 유효시간도 설정할 수 있다.
```kotlin
@Bean
fun registeredClientRepository(): RegisteredClientRepository {
    val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        // ..
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authorization: Basic {base64 encoded String}
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // client_credentials 이용
        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build()) // 토큰 2시간 유효
        .build()
    return InMemoryRegisteredClientRepository(registeredClient)
}
```

간편한 테스트를 위해 Resource Server의 역할도 겸하게 하였으며 구현이 간편한 jwt를 이용하도록 설정을 잡았다.
만약 Opaque Token을 이용하려 한다면 프레임워크 기본 구현체가 Resource Server에서 RestTemplate로 Authorization Server을 호출해야하므로 두 서버를 따로 뛰워야 하는 불편함이 있다.

### 간단한 API 코드 작성
Security 설정이 잘 되었는지 확인하기 위해 샘플 API를 작성했다.  

```kotlin
@RequestMapping("/v1/users")
@RestController
class UserController {

    @GetMapping("/me")
    fun getMyInfo(): UserInfoResponse =
        UserInfoResponse("traeper")

    data class UserInfoResponse(
        val nickname: String,
    )
}
```

### 테스트
서버를 띄우고 이것저것 테스트를 해보자. (불필요한 헤더는 생략)

1. 인증 없이 API 호출
```shell
curl -X GET http://localhost:8080/v1/users/me -v
< HTTP/1.1 401
< WWW-Authenticate: Bearer
```
인증 없이 API를 호출하면 401 응답을 받게 되며 `WWW-Authenticate: Bearer`를 받게 된다. client가 유효하지 않을 때 내려주는 헤더값인데 Bearer로 인증하라는 것을 알 수 있다. 

2. Access Token 발급 시도 (client_secret_basic 헤더 없이)
```shell
curl -X POST http://localhost:8080/custom-uri/oauth2/token\?grant_type\=client_credentials \
--header 'Content-Type: application/x-www-form-urlencoded' -v
< HTTP/1.1 401
```
client_secret_basic 헤더가 없어서 401이 발생하지만 WWW-Authenticate는 보이지 않는다. Basic 헤더를 잘 넘겨주자..! 

3. Access Token 발급 시도 (client_secret_basic 헤더와 함께)

client_secret_basic 헤더의 포맷은 `Authorization: Basic {base64 encoded string}`이다.
`{clientId}:{clientSecret}`의 복합 문장을 base64 인코딩하면 끝이다. 예시는 [테스트케이스](./src/test/kotlin/com/traeper/oauth2/authorization/ApplicationTests.kt)로 구현해뒀다.

clientSecret을 잘못 입력한 경우 401헤더와 함께 `{"error":"invalid_client"}` 같은 응답이 내려오기도 한다. clientSecret은 spring security에서 제공하는 DelegatingPasswordEncoder을 이용하므로 테스트 시 참고하자. 본 예제에서는 {noop}으로 했으니 평문 비교를 한다. 현업에서 활용할 때는 해싱을 지원하는 bcrypt 알고리즘 등으로 clientSecret을 인코딩해서 저장하면 된다. 

올바른 스펙으로 토큰 발급 API를 호출하면 마침내 Access Token을 얻을 수 있다.
```shell
curl -X POST http://localhost:8080/custom-uri/oauth2/token\?grant_type\=client_credentials \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic YWFhYTpiYmJi' -v
> Content-Type: application/x-www-form-urlencoded
> Authorization: Basic YWFhYTpiYmJi
* Mark bundle as not supporting multiuse
< HTTP/1.1 200
{"access_token":"eyJraWQiOiIzZTk2OGI0YS04Zjk2LTRkMjMtYjc5MS02MmYzMGRiYWE1M2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhIiwiYXVkIjoiYWFhYSIsIm5iZiI6MTY3Nzk1MzQzOSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjc3OTYwNjM5LCJpYXQiOjE2Nzc5NTM0Mzl9.BApI_joRvSMBcQE4c3U86oJxKwCTf3EGgC-6pNGQ7sL3PvZ6FF1S5sNUC9RqqV5qRtDxLVV1CL3h9Elzz-AzyuH3Dnvky-VGbbtnl01fqlvHX33ovEmLDLWR_wWwC4NXiClD1ad-jamOO4bvd_TVPj84W7-Ok9Sza74X5jlAYK-l0Zca8J-GpRhF92wr7UDCdPdde_FKk99dO3LWf-qbklQBgitnbgUYc1but-fRypKoTfa8uT0NCd8pw3OkDSLuJ8rVvbqCWH5ugHZtt0Z1ZasVnMKz9XFjkpcpifIr-zT9-g807zoCFktS0pFN5aMcWpENV30EQDvyOCr94-nRwA","token_type":"Bearer","expires_in":7199}
```
access_token 값은 JWT라서 길이가 제법 긴데 Opaque Token이였으면 많이 짧을 것이다. token_type은 Bearer, expires_in:7199초로 2시간인 것을 알 수 있다.

4. Access Token으로 API 호출
```shell
curl -X GET localhost:8080/v1/users/me \
--header 'Authorization: Bearer eyJraWQiOiIzZTk2OGI0YS04Zjk2LTRkMjMtYjc5MS02MmYzMGRiYWE1M2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhIiwiYXVkIjoiYWFhYSIsIm5iZiI6MTY3Nzk1MzQzOSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjc3OTYwNjM5LCJpYXQiOjE2Nzc5NTM0Mzl9.BApI_joRvSMBcQE4c3U86oJxKwCTf3EGgC-6pNGQ7sL3PvZ6FF1S5sNUC9RqqV5qRtDxLVV1CL3h9Elzz-AzyuH3Dnvky-VGbbtnl01fqlvHX33ovEmLDLWR_wWwC4NXiClD1ad-jamOO4bvd_TVPj84W7-Ok9Sza74X5jlAYK-l0Zca8J-GpRhF92wr7UDCdPdde_FKk99dO3LWf-qbklQBgitnbgUYc1but-fRypKoTfa8uT0NCd8pw3OkDSLuJ8rVvbqCWH5ugHZtt0Z1ZasVnMKz9XFjkpcpifIr-zT9-g807zoCFktS0pFN5aMcWpENV30EQDvyOCr94-nRwA
' -v
> Authorization: Bearer eyJraWQiOiIzZTk2OGI0YS04Zjk2LTRkMjMtYjc5MS02MmYzMGRiYWE1M2MiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhYWFhIiwiYXVkIjoiYWFhYSIsIm5iZiI6MTY3Nzk1MzQzOSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjc3OTYwNjM5LCJpYXQiOjE2Nzc5NTM0Mzl9.BApI_joRvSMBcQE4c3U86oJxKwCTf3EGgC-6pNGQ7sL3PvZ6FF1S5sNUC9RqqV5qRtDxLVV1CL3h9Elzz-AzyuH3Dnvky-VGbbtnl01fqlvHX33ovEmLDLWR_wWwC4NXiClD1ad-jamOO4bvd_TVPj84W7-Ok9Sza74X5jlAYK-l0Zca8J-GpRhF92wr7UDCdPdde_FKk99dO3LWf-qbklQBgitnbgUYc1but-fRypKoTfa8uT0NCd8pw3OkDSLuJ8rVvbqCWH5ugHZtt0Z1ZasVnMKz9XFjkpcpifIr-zT9-g807zoCFktS0pFN5aMcWpENV30EQDvyOCr94-nRwA
< HTTP/1.1 200
{"nickname":"traeper"}%
```

소량의 코드만으로 OAuth 2.0 Authorization Server 구현 성공!

## Spring Authorization Framework 파헤쳐 보기
프레임워크가 동작하는 원리를 좀더 파보자.

### FilterChainProxy 중 사용된 Filter 살펴보기 
![](./resources/FilterChainProxy-oauth2.png)

위 이미지는 FilterChainProxy의 filterChains 필드에 등록된 필터들을 보여준다.
Spring Security가 제공하는 10개 정도의 기본 필터 외에도 OAuth 2.0 Authorization Server 구현을 위한 필터도 약 10개 정도 추가되어 총 19개나 된다.

이번 테스트에 사용된 필터는 빨갛게 칠해진 3개다.
* OAuth2ClientAuthenticationFilter : Client로부터 받은 인증 요청을 처리하는 필터
  * ClientSecretBasicAuthenticationConverter : 테스트에 사용된 client_secret_basic Authorization 헤더에서 clientId, clientSecret을 추출한다.
  * ClientSecretAuthenticationProvider : 입력 받은 clientId, clientSecret을 검증한다.
* OAuth2TokenEndpointFilter : 토큰 발급 endpoint 필터 
  * OAuth2ClientCredentialsAuthenticationConverter : client_credentials 방식을 지원하는 OAuth2ClientCredentialsAuthenticationToken 토큰 생성 
  * OAuth2ClientCredentialsAuthenticationProvider : OAuth2ClientCredentialsAuthenticationToken 토큰을 읽고 AccessToken을 생성
* BearerTokenAuthenticationFilter : Bearer Token을 인증하는 필터
  * JwtAuthenticationProvider : jwt를 검증한다. 

만약 다른 인증 방식, endpoint, 토큰 타입 등을 활용한다면 사용되는 구현체가 달라질 수 있다.

## References
* The OAuth 2.0 Authorization Framework : https://www.rfc-editor.org/rfc/rfc6749
* The OAuth 2.1 Authorization Framework : https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07
* 프로젝트 깃헙 링크 : https://github.com/spring-projects/spring-authorization-server
* Spring Authorization Server Reference : https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html