package com.kjunw.security.controller.auth.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record LoginRequest(
        @NotBlank(message = "이메일 입력은 필수입니다.")
        @Email(message = "올바른 형식의 이메일을 입력해주세요.")
        String email,

        @NotBlank(message = "비밀번호 입력은 필수입니다.")
        @Pattern(regexp = "^(?=.*[a-zA-Z])(?=.*\\d)(?=.*[\\W_]).{8,}$", message = "영문자, 숫자, 특수기호를 포함한 8자리이상의 비밀번호를 입력해주세요.")
        String password
) {

}
