import { Inter } from 'next/font/google';
import './globals.css'; // This import is correct for your local build
import React from 'react';

const inter = Inter({ 
  subsets: ['latin'],
  variable: '--font-inter',
});

export const metadata = {
  title: 'DragonAttack - Ghidra Analysis',
  description: 'AI-Powered Ghidra Decompiler Analysis',
};

// We need to add the type for the 'children' prop
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={`${inter.variable} font-sans h-screen overflow-hidden bg-gray-900`}>
        {children}
      </body>
    </html>
  );
}
