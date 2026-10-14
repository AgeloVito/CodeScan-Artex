"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { EllipsisVertical, KeyRound, LogOut } from "lucide-react";

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { SidebarMenu, SidebarMenuButton, SidebarMenuItem, useSidebar } from "@/components/ui/sidebar";
import { useAuth } from "@/lib/auth-context";
import { getInitials } from "@/lib/utils";

import { ChangePasswordDialog } from "./change-password-dialog";

export function NavUser({
  user,
}: {
  readonly user: {
    readonly name: string;
    readonly username?: string;
    readonly email: string;
    readonly avatar: string;
    readonly isAdmin?: boolean;
  };
}) {
  const { isMobile } = useSidebar();
  const router = useRouter();
  const { signOut } = useAuth();
  const [pwOpen, setPwOpen] = React.useState(false);

  function handleLogout() {
    // signOut 会调 /api/auth/logout 并清掉本地会话（token + cookie + 账号缓存），
    // 再走客户端路由回登录页即可，不需要整页硬跳转。
    signOut();
    router.replace("/login");
  }

  // 邮箱当前账号模型里没有，第二行展示用户名（它是登录凭据，比空邮箱有用）。
  const secondary = user.username?.trim() ? user.username : user.email;

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <Avatar className="h-8 w-8 rounded-lg grayscale">
                <AvatarImage src={user.avatar || undefined} alt={user.name} />
                <AvatarFallback className="rounded-lg">{getInitials(user.name)}</AvatarFallback>
              </Avatar>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="flex min-w-0 items-center gap-1.5">
                  <span className="truncate font-medium">{user.name}</span>
                  {user.isAdmin && (
                    <Badge variant="secondary" className="h-4 shrink-0 rounded-sm px-1 text-[10px] font-normal">
                      管理员
                    </Badge>
                  )}
                </span>
                <span className="truncate text-muted-foreground text-xs">{secondary}</span>
              </div>
              <EllipsisVertical className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
            side={isMobile ? "bottom" : "right"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
                <Avatar className="h-8 w-8 rounded-lg">
                  <AvatarImage src={user.avatar || undefined} alt={user.name} />
                  <AvatarFallback className="rounded-lg">{getInitials(user.name)}</AvatarFallback>
                </Avatar>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="flex min-w-0 items-center gap-1.5">
                    <span className="truncate font-medium">{user.name}</span>
                    {user.isAdmin && (
                      <Badge variant="secondary" className="h-4 shrink-0 rounded-sm px-1 text-[10px] font-normal">
                        管理员
                      </Badge>
                    )}
                  </span>
                  <span className="truncate text-muted-foreground text-xs">{secondary}</span>
                </div>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => setPwOpen(true)}>
              <KeyRound />
              修改密码
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive">
              <LogOut />
              退出登录
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
      <ChangePasswordDialog open={pwOpen} onOpenChange={setPwOpen} />
    </SidebarMenu>
  );
}
