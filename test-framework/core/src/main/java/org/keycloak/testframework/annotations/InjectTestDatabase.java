package org.keycloak.testframework.annotations;

import org.keycloak.testframework.injection.LifeCycle;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface InjectTestDatabase {

    LifeCycle lifecycle() default LifeCycle.GLOBAL;

}