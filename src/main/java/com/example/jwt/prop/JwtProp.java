package com.example.jwt.prop;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties("com.example.jwt") // com.example.jwt 경로 하위 속성들을 지정
public class JwtProp {
    
    // com.example.jwt.secret-key -> secretKey : {인코딩된 시크릿 키}
    private String secretKey;
    
}
