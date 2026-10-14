package server

import (
	"log"
	"net/http"
	"regexp"
	"strings"
)

// =====================================================================
// 任务级权限守卫（部门所有者可写 / 部门访客只读）
//
// 这一层是所有 /api/tasks/{id}/... 与对话接口的兜底：无论具体 handler 怎么写，
// 访客（visitor）都不可能通过直接打 API 绕开前端隐藏而改动任务。
// 精细判定见 taskAccessFor；这里只做「先看能不能看、再看能不能写」。
// =====================================================================

// taskScopedPath matches the task-scoped API surface: /api/tasks/{id} and below.
var taskScopedPath = regexp.MustCompile(`^/api/tasks/(\d+)(?:/|$)`)

// isWriteMethod reports whether an HTTP method mutates state.
func isWriteMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// guardTaskAccess enforces the department permission model on task-scoped routes
// and on chat-conversation creation. It runs after requireAuth, so the account is
// always present; routes that legitimately have no task (e.g. POST /api/tasks) are
// handled by their own handlers.
func (s *Server) guardTaskAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := currentUser(r)
		if u == nil {
			// 免鉴权路径（/api/auth/status|init|login、/api/health）没有账号上下文：
			// 直接放行——其余路径 requireAuth 已经挡下未登录请求，走不到这里。
			next.ServeHTTP(w, r)
			return
		}
		write := isWriteMethod(r.Method)
		if m := taskScopedPath.FindStringSubmatch(r.URL.Path); m != nil {
			if t, ok := s.m.Task(m[1]); ok && t != nil {
				access := s.taskAccessFor(u, t)
				switch {
				case write && !access.Write:
					writeErr(w, 403, "只读权限：部门访客不能修改或控制任务")
					return
				case !write && !access.View:
					// 不暴露「存在但无权查看」的任务，统一按不存在处理。
					writeErr(w, 404, "task not found")
					return
				}
			} else if !u.IsAdmin {
				// 内存里没有这个任务（历史/归档/已删除，或还没被 manager 加载）：拿不到它的
				// 部门与创建者，就没有依据判权限。这里必须默认拒绝——否则守卫会被"内存里
				// 查不到"绕过，非管理员能对任意历史任务 id 执行暂停/删除等写操作。
				writeErr(w, 404, "task not found")
				return
			}
		}
		// 对话：访客不能发起/继续任何对话（任务内对话按该任务的写权限判定）。
		if write && (r.URL.Path == "/api/chat" || r.URL.Path == "/api/conversations" ||
			strings.HasPrefix(r.URL.Path, "/api/conversations/")) {
			if tid := strings.TrimSpace(r.URL.Query().Get("task")); tid != "" {
				if t, ok := s.m.Task(tid); ok && t != nil {
					if !s.taskWriteAllowed(u, t) {
						writeErr(w, 403, "只读权限：部门访客不能发起对话")
						return
					}
				} else if !u.IsAdmin {
					// 同任务守卫：内存里查不到就没法判权限，默认拒绝（管理员不受限）。
					writeErr(w, 404, "task not found")
					return
				}
			} else if strings.HasSuffix(r.URL.Path, "/messages") || r.URL.Path == "/api/chat" {
				if !s.permissionsFor(u).CanChat {
					writeErr(w, 403, "只读权限：部门访客不能发起对话")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireBatchTaskWrite 是批量接口的权限闸：批量暂停/分类/归档走的是
// POST /api/tasks/control/batch 这类「路径里没有任务 id」的接口，路径正则守卫覆盖不到，
// 而它们真实作用的对象在 body 的 task_ids 里。这里逐个解析：只要有一个任务当前账号只有
// 读权限，就整体拒绝（宁可整批失败，也不要静默跳过——跳过会让用户以为操作成功了）。
func (s *Server) requireBatchTaskWrite(w http.ResponseWriter, r *http.Request, ids []string) bool {
	u := currentUser(r)
	if u == nil {
		writeErr(w, 401, "未授权")
		return false
	}
	if u.IsAdmin {
		return true
	}
	for _, id := range ids {
		t, ok := s.m.Task(strings.TrimSpace(id))
		if !ok || t == nil {
			continue // 不存在的任务交给各自的 handler 报 "task not found"
		}
		if !s.taskWriteAllowed(u, t) {
			writeErr(w, 403, "只读权限：部门访客不能修改或控制任务（任务 #"+t.ID+"）")
			return false
		}
	}
	return true
}

// taskDTOWithAccess 生成带权限位的任务 DTO：列表/详情/变更接口都用它，保证前端拿到的
// can_write 与后端判定一致。变更接口（创建、改分类、改元数据、改部门、开启）尤其重要——
// 少了这一位，部门所有者创建任务后立刻拿到 can_write=false，详情页会把「开启任务」藏起来。
func (s *Server) taskDTOWithAccess(r *http.Request, t *Task) TaskDTO {
	dto := taskDTO(t, s.resolvedTaskStatus(t))
	dto.CanWrite = s.taskWriteAllowed(currentUser(r), t)
	return dto
}

// POST /api/tasks/{id}/start — 用户进入任务详情后【手动开启】任务。
// 创建任务时不再自动开跑，只有这里（或显式 auto_start）才会走 launchTask。
func (s *Server) startTask(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok || t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.taskWriteAllowed(currentUser(r), t) {
		writeErr(w, 403, "只读权限：部门访客不能开启任务")
		return
	}
	status := s.resolvedTaskStatus(t)
	switch {
	case status == "running":
		writeErr(w, 409, "任务已经在运行中")
		return
	case status == "queued":
		writeErr(w, 409, "任务已在等待队列中")
		return
	case isTerminalStatus(status):
		writeErr(w, 409, "任务已结束，如需继续请使用「重跑」")
		return
	case status == "paused":
		writeErr(w, 409, "任务已暂停，请使用「继续」")
		return
	}
	if strings.TrimSpace(t.SourcePath) == "" {
		if me := currentUser(r); me == nil || !me.IsAdmin {
			writeErr(w, 400, "该任务还没有源码包，请重新上传后再开启")
			return
		}
		log.Printf("[task] 管理员开启无源码任务 #%s（未上传源码包）", t.ID)
	}
	// 没装 LLM 就开不动：engine 处于 idle，任务会一直停在 created，用户只会看到
	// 「点了开启但状态没变」。这里直接说清楚要去哪配，而不是返回 200 让人干等。
	// 用 ReadyFor(t) 而不是 Ready()：任务自带 LLM 配置链时，即使没有全局默认也能跑。
	if !s.engine.ReadyFor(t) {
		writeErr(w, 409, "尚未配置可用的 LLM，无法开启任务：请到「系统配置 → LLM」填写模型与 API Key 后重试")
		return
	}
	log.Printf("[task] 手动开启任务 #%s（部门=%v）", t.ID, t.DepartmentID)
	s.launchTask(t, t.Description+" "+t.Goal, false)
	writeJSON(w, 200, s.taskDTOWithAccess(r, t))
}
