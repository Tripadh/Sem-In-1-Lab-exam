package com.example.jwtrbac.dto.response;

import java.time.LocalDateTime;

public class AdminDashboardResponse {

    private String message;
    private long totalUsers;
    private LocalDateTime serverTime;
    private String systemStatus;

    public AdminDashboardResponse() {
    }

    public AdminDashboardResponse(String message, long totalUsers, LocalDateTime serverTime, String systemStatus) {
        this.message = message;
        this.totalUsers = totalUsers;
        this.serverTime = serverTime;
        this.systemStatus = systemStatus;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public long getTotalUsers() {
        return totalUsers;
    }

    public void setTotalUsers(long totalUsers) {
        this.totalUsers = totalUsers;
    }

    public LocalDateTime getServerTime() {
        return serverTime;
    }

    public void setServerTime(LocalDateTime serverTime) {
        this.serverTime = serverTime;
    }

    public String getSystemStatus() {
        return systemStatus;
    }

    public void setSystemStatus(String systemStatus) {
        this.systemStatus = systemStatus;
    }
}
