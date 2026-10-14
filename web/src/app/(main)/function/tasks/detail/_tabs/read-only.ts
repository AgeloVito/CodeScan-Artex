// 部门访客（后端返回 task.can_write === false）在任务详情里只能查看。
// 所有可变更控件统一用这里的文案说明原因，措辞与后端 403「只读权限：部门访客不能…」保持一致；
// 前端禁用只是体验优化，后端仍会独立拒绝请求。
export const READ_ONLY_TITLE = "部门访客为只读，无操作权限";

/** 可写时用业务 title，只读时统一改成只读原因（悬停即可知道为什么点不动）。 */
export function writeTitle(canWrite: boolean, title: string): string {
  return canWrite ? title : READ_ONLY_TITLE;
}
