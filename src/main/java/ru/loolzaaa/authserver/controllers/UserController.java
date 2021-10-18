package ru.loolzaaa.authserver.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.authserver.dto.CreateUserRequestDTO;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.services.UserControlService;

import javax.validation.Valid;
import java.util.List;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class UserController {

    private final UserControlService userControlService;

    @GetMapping(value = "/fast/user/get/{username}", produces = "application/json")
    ResponseEntity<UserPrincipal> getUserByUsername(@PathVariable("username") String username,
                                    @RequestParam(value = "app", required = false) String app) {
        UserPrincipal userPrincipal = userControlService.getUserByUsername(username, app);
        return ResponseEntity.status(HttpStatus.OK).body(userPrincipal);
    }

    @GetMapping(value = "/fast/user/{role}", produces = "application/json")
    ResponseEntity<List<UserPrincipal>> getUsersByRole(@PathVariable("role") String role, @RequestParam(value = "app") String app) {
        List<UserPrincipal> users = userControlService.getUsersByRole(role, app);
        return ResponseEntity.status(HttpStatus.OK).body(users);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value = "/user/create", consumes = "application/json", produces = "application/json")
    ResponseEntity<RequestStatusDTO> createUser(@RequestParam("app") String app,
                                                @Valid @RequestBody CreateUserRequestDTO user,
                                                BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new RequestErrorException("Can't create DTO for new user");
        }
        RequestStatusDTO requestStatusDTO = userControlService.createUser(app, user);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "/user/{username}/delete", produces = "application/json")
    ResponseEntity<RequestStatusDTO> deleteUser(@PathVariable("username") String username,
                                                @RequestParam(name = "password", required = false) String password) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteUser(username, password);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PostMapping(value = "/user/{username}/password/change", produces = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserPassword(@PathVariable("username") String username,
                                                        @RequestParam("oldPassword") String oldPassword,
                                                        @RequestParam("newPassword") String newPassword) {
        RequestStatusDTO requestStatusDTO = userControlService.changeUserPassword(username, oldPassword, newPassword);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping(value = "/user/{username}/password/reset", produces = "application/json")
    ResponseEntity<RequestStatusDTO> resetUserPassword(@PathVariable("username") String username,
                                                       @RequestParam("newPassword") String newPassword) {
        RequestStatusDTO requestStatusDTO = userControlService.resetUserPassword(username, newPassword);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PutMapping(value = "/user/{username}/config/{app}/edit", consumes = "application/json", produces = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserConfig(@PathVariable("username") String username, @PathVariable("app") String app,
                                                      @RequestBody JsonNode config, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new RequestErrorException("Can't create JsonNode for config");
        }
        RequestStatusDTO requestStatusDTO = userControlService.changeApplicationConfigForUser(username, app, config);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "/user/{username}/config/{app}/delete", produces = "application/json")
    ResponseEntity<RequestStatusDTO> deleteUserConfig(@PathVariable("username") String username, @PathVariable("app") String app) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteApplicationConfigForUser(username, app);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PutMapping(value = "/user/temporary/create", produces = "application/json")
    ResponseEntity<RequestStatusDTO> createTemporaryUser(@RequestParam("username") String username,
                                                         @RequestParam("dateFrom") long dateFrom,
                                                         @RequestParam("dateTo") long dateTo) {
        RequestStatusDTO requestStatusDTO = userControlService.createTemporaryUser(username, dateFrom, dateTo);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }
}
