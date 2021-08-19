package ru.loolzaaa.authserver.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.loolzaaa.authserver.dto.CreateUserRequestDTO;
import ru.loolzaaa.authserver.dto.RequestStatusDTO;
import ru.loolzaaa.authserver.exception.RequestErrorException;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;
import ru.loolzaaa.authserver.services.UserControlService;

import javax.validation.Valid;

@RequiredArgsConstructor
@Controller
@RequestMapping("/api")
public class UserController {

    private final UserRepository userRepository;

    private final UserControlService userControlService;

    @GetMapping("/fast/user/get/{username}")
    @ResponseBody
    UserPrincipal getUserByUsername(@PathVariable("username") String username,
                                    @RequestParam(value = "app", required = false) String app) {
        User user = userRepository.findByLogin(username).orElse(null);
        if (user == null) {
            return null;
        }
        try {
            return new UserPrincipal(user, app);
        } catch (Exception e) {
            return null;
        }
    }

    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    @PutMapping(value = "/user/create", consumes = "application/json")
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
    @ResponseBody
    @DeleteMapping("/user/{username}/delete")
    ResponseEntity<RequestStatusDTO> deleteUser(@PathVariable("username") String username,
                                                @RequestParam(name = "password", required = false) String password) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteUser(username, password);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @ResponseBody
    @PostMapping("/user/{username}/password/change")
    ResponseEntity<RequestStatusDTO> changeUserPassword(@PathVariable("username") String username,
                                                        @RequestParam("oldPassword") String oldPassword,
                                                        @RequestParam("newPassword") String newPassword) {
        RequestStatusDTO requestStatusDTO = userControlService.changeUserPassword(username, oldPassword, newPassword);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    @PostMapping("/user/{username}/password/reset")
    ResponseEntity<RequestStatusDTO> resetUserPassword(@PathVariable("username") String username,
                                                       @RequestParam("newPassword") String newPassword) {
        RequestStatusDTO requestStatusDTO = userControlService.resetUserPassword(username, newPassword);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @ResponseBody
    @PutMapping(value = "/user/{username}/config/{app}/edit", consumes = "application/json")
    ResponseEntity<RequestStatusDTO> changeUserConfig(@PathVariable("username") String username, @PathVariable("app") String app,
                                                      @RequestBody JsonNode config, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            throw new RequestErrorException("Can't create JsonNode for config");
        }
        RequestStatusDTO requestStatusDTO = userControlService.changeApplicationConfigForUser(username, app, config);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @ResponseBody
    @DeleteMapping("/user/{username}/config/{app}/delete")
    ResponseEntity<RequestStatusDTO> deleteUserConfig(@PathVariable("username") String username, @PathVariable("app") String app) {
        RequestStatusDTO requestStatusDTO = userControlService.deleteApplicationConfigForUser(username, app);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }

    @ResponseBody
    @PutMapping("/user/temporary/create")
    ResponseEntity<RequestStatusDTO> createTemporaryUser(@RequestParam("username") String username,
                                                         @RequestParam("dateFrom") long dateFrom,
                                                         @RequestParam("dateTo") long dateTo) {
        RequestStatusDTO requestStatusDTO = userControlService.createTemporaryUser(username, dateFrom, dateTo);
        return ResponseEntity.status(requestStatusDTO.getStatusCode()).body(requestStatusDTO);
    }
}
