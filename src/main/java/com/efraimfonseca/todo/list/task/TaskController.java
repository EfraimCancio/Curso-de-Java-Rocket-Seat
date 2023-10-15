package com.efraimfonseca.todo.list.task;

import com.efraimfonseca.todo.list.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/tasks")
public class TaskController {

    @Autowired
    private ITaskRepository taskRepository;

    @PostMapping("/")
    public ResponseEntity create(@RequestBody TaskModel taskModel, HttpServletRequest request) {
        //Atribuindo dinamicamente o Id do usuario autenticado à task
        var idUser = request.getAttribute("idUser");
        taskModel.setIdUser((UUID) idUser);

        //Verificando se a Data de criação é válida
        var currentDate = LocalDateTime.now();
//        if (currentDate.isAfter(taskModel.getStartAt()) || currentDate.isAfter(taskModel.getEndAt())) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Coloque uma data válida");
//        }
//        if (taskModel.getStartAt().isAfter(taskModel.getEndAt())) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("A data de inicio não deve ser menor que a data de termino");
//        }


        var task = this.taskRepository.save(taskModel);
        return ResponseEntity.status(HttpStatus.OK).body(task);
    }

    @GetMapping("/")
    public List<TaskModel> list(HttpServletRequest request) {

        var idUser = request.getAttribute("idUser");
        var tasks = this.taskRepository.findByIdUser((UUID)idUser);
        return tasks;
    }

    @PostMapping("/{id}")
    public TaskModel update(@RequestBody TaskModel taskModel, @PathVariable UUID id, HttpServletRequest request) {


        var task = this.taskRepository.findById(id).orElse(null);


        if (task == null) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("A tarefa não existe.");

        }

        var idUser = request.getAttribute("idUser");

        if (!task.getIdUser().equals(idUser)) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Usuario não tem permissão para alterar a tarefa.");
        }

        Utils.copyNonNullProperties(taskModel, task);

        var taskUpdated = this.taskRepository.save(task);
        return  taskUpdated;
    }
}
