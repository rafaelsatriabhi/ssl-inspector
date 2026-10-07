import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata = {
  title: "SSL Inspector",
  description: "Inspect a server's TLS setup and certificate chain, and get an A+ to F grade.",
};

export default function RootLayout({ children }) {
  return (
    // The font variables go on <html> so the tokens in globals.css (declared on :root) can use them.
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
