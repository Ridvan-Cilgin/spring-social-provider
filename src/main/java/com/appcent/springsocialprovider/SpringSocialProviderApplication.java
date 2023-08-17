package com.appcent.springsocialprovider;

import com.appcent.springsocialprovider.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProperties.class)
public class SpringSocialProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSocialProviderApplication.class, args);
    }

}
