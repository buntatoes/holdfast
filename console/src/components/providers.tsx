"use client";

import { ThemeProvider } from "next-themes";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { HoldfastProvider } from "@/components/holdfast-provider";
import { AppHeader } from "@/components/app-header";
import { SessionStrip } from "@/components/session-strip";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" forcedTheme="dark" enableSystem={false}>
      <TooltipProvider>
        <HoldfastProvider>
          <div className="flex min-h-dvh flex-col bg-background text-foreground">
            <AppHeader />
            <SessionStrip />
            <main className="flex min-h-0 flex-1 flex-col">{children}</main>
          </div>
          <Toaster theme="dark" position="bottom-right" />
        </HoldfastProvider>
      </TooltipProvider>
    </ThemeProvider>
  );
}
