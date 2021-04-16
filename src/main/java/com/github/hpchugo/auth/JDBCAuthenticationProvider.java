package com.github.hpchugo.auth;

import javax.annotation.Nullable;
import javax.inject.Singleton;

import com.github.hpchugo.auth.persistence.UserEntity;
import com.github.hpchugo.auth.persistence.UserRepository;
import io.micronaut.http.HttpRequest;
import io.micronaut.security.authentication.*;
import io.reactivex.BackpressureStrategy;
import io.reactivex.Flowable;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

@Singleton
public class JDBCAuthenticationProvider implements AuthenticationProvider {
    private static final Logger LOG = LoggerFactory.getLogger(JDBCAuthenticationProvider.class);
    private final UserRepository users;

    public JDBCAuthenticationProvider(final UserRepository users) {
        this.users = users;
    }

    @Override
    public Publisher<AuthenticationResponse> authenticate(@Nullable HttpRequest<?> httpRequest, AuthenticationRequest<?, ?> authenticationRequest) {
        final String identity = authenticationRequest.getIdentity().toString();
        LOG.debug("User {} tries to login...", identity);
        return Flowable.create(emitter -> {
            Optional<UserEntity> maybeUser = users.findByEmail(identity);
            if(maybeUser.isPresent()){
                LOG.debug("Found user: {}", maybeUser.get().getEmail());
                final String secret = authenticationRequest.getSecret().toString();
                if(maybeUser.get().getPassword().equals(secret)){
                    LOG.debug("User logger in.");
                    final HashMap<String, Object> attributes = new HashMap<>();
                    attributes.put("hair_color", "brown");
                    attributes.put("language", "en");
                    final UserDetails userDetails = new UserDetails(
                            identity,
                            Collections.singletonList("ROLE_USER"),
                            attributes);
                    emitter.onNext(userDetails);
                    emitter.onComplete();
                    return;
                }else{
                    LOG.debug("Wrong password provider for user: {}", identity);
                }
            }else{
                LOG.debug("No user found with email: {}", identity);
            }
            emitter.onError(new AuthenticationException(new AuthenticationFailed("Wrong username or password!")));
        }, BackpressureStrategy.ERROR);
    }
}
