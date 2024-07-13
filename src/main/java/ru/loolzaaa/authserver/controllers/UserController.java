package ru.loolzaaa.authserver.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.authserver.dto.CreateUserRequestDTO;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.services.UserControlService;

import java.util.List;
import java.util.Locale;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class UserController {

    private static final GrantedAuthority adminGrantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");

    private final MessageSource messageSource;

    private final UserControlService userControlService;

    @GetMapping(value = {"/user/{username}", "/fast/user/{username}"}, produces = "application/json")
    UserPrincipal getUserByUsername(@PathVariable("username") String username,
                                    @RequestParam(value = "app", required = false) String app,
                                    Locale locale) {
        return userControlService.getUserByUsername(username, app, locale);
    }

    @GetMapping(value = {"/users", "/fast/users"}, produces = "application/json")
    List<UserPrincipal> getUsersByAuthority(@RequestParam(value = "app") String app,
                                            @RequestParam("authority") String authority,
                                            Locale locale) {
        return userControlService.getUsersByAuthority(app, authority, locale);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value = "/user", consumes = "application/json", produces = "application/json")
    ResponseEntity<RequestStatusDTO> createUser(@RequestParam("app") String app,
                                                @Valid @RequestBody CreateUserRequestDTO user,
                                                BindingResult bindingResult,
                                                Locale locale) {
        if (bindingResult.hasErrors()) {
            String message = messageSource.getMessage("userControl.create.parseError", null, locale);
            throw new RequestErrorException(message);
        }
        RequestStatusDTO requestStatusDTO = userControlService.createUser(app, user, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "/user/{username}", produces = "application/json")
    ResponseEntity<RequestStatusDTO> deleteUser(@PathVariable("username") String username,
                                                @RequestParam(name = "password", required = false) String password,
                                                Locale locale) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteUser(username, password, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PatchMapping(value = "/user/{username}/lock", produces = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserLockStatus(@PathVariable("username") String username,
                                                          @RequestParam(value = "enabled", required = false) Boolean enabled,
                                                          @RequestParam(value = "lock", required = false) Boolean lock,
                                                          Locale locale) {
        RequestStatusDTO requestStatusDTO = userControlService.changeUserLockStatus(username, enabled, lock, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PostMapping(value = "/user/{username}/password/change", produces = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserPassword(@PathVariable("username") String username,
                                                        @RequestParam("oldPassword") String oldPassword,
                                                        @RequestParam("newPassword") String newPassword,
                                                        Locale locale) {
        RequestStatusDTO requestStatusDTO = userControlService.changeUserPassword(username, oldPassword, newPassword, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(value = "/user/{username}/password/reset", produces = "application/json")
    ResponseEntity<RequestStatusDTO> resetUserPassword(@PathVariable("username") String username,
                                                       @RequestParam("newPassword") String newPassword,
                                                       Locale locale) {
        RequestStatusDTO requestStatusDTO = userControlService.resetUserPassword(username, newPassword, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PatchMapping(value = {"/user/{username}/config/{app}", "/fast/user/{username}/config/{app}"},
            consumes = "application/json", produces = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserConfig(@PathVariable("username") String username,
                                                      @PathVariable("app") String app,
                                                      @RequestBody JsonNode config,
                                                      BindingResult bindingResult,
                                                      Locale locale) {
        if (bindingResult.hasErrors()) {
            String message = messageSource.getMessage("userControl.changeConfig.parseError", null, locale);
            throw new RequestErrorException(message);
        }
        RequestStatusDTO requestStatusDTO = userControlService.changeApplicationConfigForUser(username, app, config, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "/user/{username}/config/{app}", produces = "application/json")
    ResponseEntity<RequestStatusDTO> deleteUserConfig(@PathVariable("username") String username,
                                                      @PathVariable("app") String app,
                                                      Locale locale) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteApplicationConfigForUser(username, app, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PutMapping(value = "/user/temporary", produces = "application/json")
    ResponseEntity<RequestStatusDTO> createTemporaryUser(Authentication authentication,
                                                         @RequestParam("username") String username,
                                                         @RequestParam("dateFrom") long dateFrom,
                                                         @RequestParam("dateTo") long dateTo,
                                                         Locale locale) {
        if (!isUserPermitToCreateTemporaryUser(authentication, username)) {
            String message = messageSource.getMessage("userControl.temporary.permitMessage", null, locale);
            throw new RequestErrorException(message);
        }
        RequestStatusDTO requestStatusDTO = userControlService.createTemporaryUser(username, dateFrom, dateTo, locale);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    private boolean isUserPermitToCreateTemporaryUser(Authentication authentication, String username) {
        boolean isUserAdmin = authentication.getAuthorities().contains(adminGrantedAuthority);
        if (authentication.getPrincipal() instanceof UserPrincipal userPrincipal) {
            return isUserAdmin || userPrincipal.getUser().getLogin().equals(username);
        }
        return isUserAdmin;
    }
}
