package moe.cnkirito.security.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

/**
 * @author 徐靖峰
 * Date 2018-04-19
 */
@SpringBootApplication
public class SpringBoot2Oauth2App {

    public static void main(String[] args) {
        SpringApplication.run(SpringBoot2Oauth2App.class, args);
    }

}
