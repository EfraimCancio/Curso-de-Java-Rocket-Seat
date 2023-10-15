package com.efraimfonseca.todo.list.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.efraimfonseca.todo.list.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {



    @Autowired
    IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        //Validando se está ou não na rota correta
        var servletPath = request.getServletPath();
        if (servletPath.startsWith("/tasks/")) {

            //Pegar a autenticação e decodificá-la (usuário e senha)
            var authorization = request.getHeader("Authorization");
            var authEncoded = authorization.substring("Basic".length()).trim();
            byte[] authDecode = Base64.getDecoder().decode(authEncoded);
            var authString = new String(authDecode);
            String[] credentials = authString.split(":");
            String userName = credentials[0];
            String password = credentials[1];

            //Validar usuário
            var user = this.userRepository.findByUserName(userName);
            if (user == null) {
                response.sendError(401, "Usuário sem autorização");
            } else {
                //Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified) {

                    //Segue Viagem
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401, "A senha está incorreta");
                }

            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
