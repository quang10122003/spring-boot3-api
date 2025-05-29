package com.springboot.spring_hello.configuration;

import java.security.KeyStore.SecretKeyEntry;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.springboot.spring_hello.enums.Roles;

import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;

@Configuration
@EnableWebSecurity // Thêm annotation này để kích hoạt Spring Security
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@EnableMethodSecurity // phân quyền dự theo method
public class SecurityConfig {

    String[] PUBLIC_ENDPOINT = { "/users/create", "/auth/login", "/auth/Introspect" };
    @Value("${jwt.signerKey}")
    @NonFinal
    protected String SIGNER_KEY;

    // cấu hình các endpoint
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // cấu hình endpoint public ko CẦN  authentication
                .authorizeHttpRequests(request -> request.requestMatchers(HttpMethod.POST, PUBLIC_ENDPOINT).permitAll()
                        // cấu hình endpoint chỉ có admin mới truy cập đc
                        // .requestMatchers(HttpMethod.GET,
                        // "/users/getlist").hasAnyRole(Roles.ADMIN.toString())

                        // cấu hình endpoint ko public phải có authentication
                        .anyRequest().authenticated());
        // cấu hinh csrf
        httpSecurity.csrf(httpSecirityCsrfConfigurer -> httpSecirityCsrfConfigurer.disable());

        // cấu hình auth token đến vào endpoint private
        // Cấu hình ứng dụng như một OAuth2 Resource Server sử dụng JWT để xác thực
        // người dùng.
        // Spring sẽ sử dụng jwtDecoder() để giải mã và xác thực các JWT token từ client
        // gửi lên.
        httpSecurity.oauth2ResourceServer(
                oauth2 -> oauth2.jwt(jwtConfiguger -> jwtConfiguger.decoder(jwtDecoder())
                        // triển khai custum scope role
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )

                        // Cấu hình entry point tùy chỉnh khi xảy ra lỗi xác thực (unauthenticated)
                        // Nếu người dùng truy cập vào tài nguyên mà không có token hoặc token không hợp
                        // lệ,
                        // JwtAuthenticationEntryPoint sẽ được gọi để trả về phản hồi JSON phù hợp.
                        .authenticationEntryPoint(new JwtAuthenticationEntryPoint())

        );

        return httpSecurity.build();
    }

    /**
 * Cấu hình JwtAuthenticationConverter để chuyển đổi các claims từ JWT token
 * thành danh sách GrantedAuthority mà Spring Security có thể hiểu và sử dụng.
 *
 * Mặc định, Spring Security sẽ thêm tiền tố "SCOPE_" vào mỗi quyền (authority),
 * nhưng ở đây ta loại bỏ tiền tố đó bằng cách gọi setAuthorityPrefix(""),
 * nhằm giữ nguyên tên quyền đúng như trong token (ví dụ: "ADMIN", "USER").
 *
 */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    // cung cấp cấu hình verity token cho authencation
    @Bean
    JwtDecoder jwtDecoder() {
        SecretKeySpec secretKeySpec = new SecretKeySpec(SIGNER_KEY.getBytes(), "HS512");
        NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withSecretKey(secretKeySpec)
                .macAlgorithm(MacAlgorithm.HS512)
                .build();
        return nimbusJwtDecoder;
    };

    // bean Bcrypt để dùng nhiều nơi
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }
}
