package net.hauntedstudio.timetable.timetableservice.controller;

import net.hauntedstudio.timetable.timetableservice.filter.JwtAuthFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/timetable")
public class TimeTableController {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);


    @GetMapping("/get")
    @PreAuthorize("hasRole('ROLE_STUDENT')")
    public String getTimeTable() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            logger.error("No authentication found in SecurityContext");
            return "No authentication";
        }
        logger.info("Authenticated user: {}", authentication.getPrincipal());
        return "Time Table";
    }
}
