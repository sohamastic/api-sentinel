import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = {
  title: 'API Sentinel | Security Operations',
  description:
    'Inspect API traffic, investigate threats, and test protection policies in a controlled security lab.',
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
