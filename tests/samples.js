/* ============================================================================
 * tests/samples.js — 31 real-looking messages (20 scams + 11 legitimate)
 * used by both the Node runner and the browser test page. Each sample lists
 * what the engine SHOULD find (expected level band + attack ids) and what it
 * MUST NOT claim (noFalse).
 * ==========================================================================*/
(function (g) {
  'use strict';
  g.SAMPLES = [

    /* ═════════════════════ SCAM SAMPLES ═════════════════════ */

    { name: 'Fake bank KYC (SBI-style SMS)',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['fake_bank_kyc'], noFalse: [],
      input: { mode: 'message',
        text: 'Dear Customer, your SBI account will be BLOCKED today. Update your KYC immediately by clicking http://sbi-kyc-verify.info within 2 hours to avoid suspension. -Bank Team' } },

    { name: 'ICICI KYC phishing (classic sample)',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['fake_bank_kyc'],
      input: { mode: 'message',
        text: 'Dear Customer, your ICICI a/c will be BLOCKED today. Update your KYC immediately by clicking http://icici-kyc-verify.in within 2 hours to avoid suspension. -Bank Team' } },

    { name: 'OTP theft / vishing (Paytm)',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['otp_theft', 'vishing'],
      input: { mode: 'message',
        text: 'Your Paytm login code is 449128. Share this OTP with our agent to complete the refund verification. Call now 011-4826-9900.' } },

    { name: 'UPI collect-request / refund QR',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['upi_fraud'],
      input: { mode: 'message',
        text: 'You have received a payment request of Rs. 9,999. Your refund of Rs. 4,999 is pending. Scan this QR to claim it now. Reply YES to authorize.' } },

    { name: 'Fake refund needs a fee',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['refund_scam'],
      input: { mode: 'message',
        text: 'Your Amazon refund of Rs.12,000 is unclaimed. Pay a refundable processing fee of Rs.500 to release the amount to your bank account.' } },

    { name: 'CEO / whaling transfer',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['whaling'],
      input: { mode: 'message',
        text: 'Hi, this is the CEO Harish. I am in a meeting with the auditors. Kindly transfer Rs. 85,000 to this new account urgently and keep it between us. Do not call payroll.' } },

    { name: 'Job / work-from-home fee',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['job_scam'],
      input: { mode: 'message',
        text: 'Congratulations! You are hired for the Work From Home job. Pay Rs.250 registration fee to start earning Rs.3,500 daily. WhatsApp 91 987xx for the task list.' } },

    { name: 'Lottery prize fee',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['lottery_prize'],
      input: { mode: 'message',
        text: 'You have won Rs. 25,00,000 in the Mega Lucky Draw! Pay Rs. 8,500 processing fee to claim your prize. Winning no: W-4492.' } },

    { name: 'Investment / crypto trading group',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['investment_scam'],
      input: { mode: 'message',
        text: 'Join our trading group. Earn guaranteed 20% monthly returns on crypto. VIP signals, no experience needed. Withdrawals may require a small fee.' } },

    { name: 'Digital arrest (police impersonation)',
      expectLevels: ['high', 'critical'], minScore: 70, expectAttacks: ['gov_impersonation'],
      input: { mode: 'message',
        text: 'This is the cyber crime cell. Your parcel has illegal contents and a case has been filed against you. Transfer money to the safe account to avoid digital arrest. Call 75xx.' } },

    { name: 'Courier customs fee',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['delivery_courier'],
      input: { mode: 'message',
        text: 'Your India Post parcel 3342789 is held at customs. Pay the customs clearance fee of Rs.589 to release the package. Delivery attempt failed. Click rpy.in/pay to pay.' } },

    { name: 'Electricity disconnection threat',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['utility_scam'],
      input: { mode: 'message',
        text: 'BESCOM: Your electricity bill is overdue. Your connection will be disconnected in 4 hours. Pay immediately by scanning this QR code to avoid disconnection.' } },

    { name: 'Sextortion blackmail',
      expectLevels: ['high', 'critical'], minScore: 70, expectAttacks: ['sextortion'],
      input: { mode: 'message',
        text: 'I have recorded your screen during a video call. Send $500 within 24 hours or I will share the video with your family and friends. Pay now to stop this.' } },

    { name: 'Tech support + AnyDesk',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['tech_support'],
      input: { mode: 'message',
        text: 'Windows support: your PC has been infected. Our engineer will fix it. Install AnyDesk and share the 9-digit code, then confirm your login password at windows-secure.top.' } },

    { name: 'Romance crisis',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['romance_scam'],
      input: { mode: 'message',
        text: 'My love, I have fallen for you. My flight is stuck at the airport and I need $900 for a ticket to come meet you. My dear, please send money today, I will repay.' } },

    { name: 'Netflix phishing email',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['brand_impersonation'],
      mode: 'email',
      input: { mode: 'email', sender: 'Netflix Support <support@netflix-login.verify-account.net>',
        replyTo: 'noreply@secure-mail.ru',
        subject: 'Your Netflix account will be suspended today',
        body: 'Dear user, your Netflix subscription could not be charged. Confirm your payment details now to avoid suspension: http://netflix-account-verify.xyz/login' } },

    { name: 'Invoice payment-change (BEC) email',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['bec_invoice'],
      mode: 'email',
      input: { mode: 'email', sender: 'Accounts - Sharma Suppliers <billing@sharma-suppliers.com>',
        subject: 'Updated bank details for invoice INV-2026-0812',
        body: 'Hi, please note we have changed our bank account. Kindly pay invoice INV-2026-0812 to our new account: Beneficiary Sharma Traders, A/C 50100234567812, IFSC HDFC0001234. Urgent: payment due tomorrow.' } },

    { name: 'Love scam advance-fee variant',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['romance_scam'],
      input: { mode: 'message',
        text: 'Hello sweetheart. I am an oil rig engineer. I love you already. My account is frozen, please help me with $500 to pay cargo fees so I can come to you. Forever yours.' } },

    { name: 'Malware via password-protected zip',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['malware_delivery'],
      mode: 'email',
      input: { mode: 'email', sender: 'Invoice Desk <invoices@little-sons.tk>', subject: 'Invoice for review',
        body: 'Please open the attached invoice.zip. Password is: 9912. Enable macros in the file to view the breakdown.' } },

    { name: 'Whaling via Gmail-branded phishing',
      expectLevels: ['medium', 'high', 'critical'], minScore: 50, expectAttacks: ['phishing'],
      input: { mode: 'message',
        text: 'GOOGLE: Your account had unusual logins. Verify your profile now by logging in at https://accounts.google.com-secure.verify.today to avoid being locked out.' } },

    /* ═════════════════════ LEGIT SAMPLES ═════════════════════ */

    { name: 'Dinner text to mom', minScore: 0, maxScore: 24, expectLevels: ['safe'], expectAttacks: [],
      input: { mode: 'message', text: 'Hi Mom, I will be home at 6 for dinner. Please pick up some bread on the way. Love you!' } },

    { name: 'Amazon order shipped', minScore: 0, maxScore: 34, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Your Amazon order #505-8821301-2345 has shipped and will arrive Tuesday. Track: https://www.amazon.in/gp/css/ship-track' } },

    { name: 'Bank statement ready (real HDFC)', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Dear Arun, your HDFC monthly statement is ready. View it inside the official HDFC Mobile app. You do not need to do anything else.' } },

    { name: 'Genuine OTP with do-not-share', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Your OTP for login is 123456. Valid for 10 minutes. Do not share this OTP with anyone. -HDFC Bank' } },

    { name: 'Doctor appointment confirmation', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Dear Anu, your appointment with Dr Mehta is confirmed for Friday 10:00 am. Please arrive 10 minutes early. Reply STOP to opt out of reminders.' } },

    { name: 'Netflix receipt email (real domain)', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      mode: 'email',
      input: { mode: 'email', sender: 'Netflix <info@netflix.com>', subject: 'Your Netflix receipt',
        body: 'Thanks for your continued membership, Rahul. Payment of $18.99 was received for May 1 to Jun 1. You can view your invoice in the Account section on netflix.com.' } },

    { name: 'Uber trip receipt', minScore: 0, maxScore: 34, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Your Uber trip is complete. Paid Rs.150 by UPI. Thanks for riding with us! See you soon.' } },

    { name: 'Google password reset email', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      mode: 'email',
      input: { mode: 'email', sender: 'Google <no-reply@accounts.google.com>', subject: 'Security alert',
        body: 'Hi, someone just used your password. If this was you, you can ignore this email. If not, please reset your password: https://accounts.google.com/signin/recovery and review recent security events.' } },

    { name: 'Electricity bill via official app', minScore: 0, maxScore: 34, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Your electricity bill for March is Rs.1,240. Pay using the official BESCOM app before the due date printed on your bill.' } },

    { name: 'Team standup reminder with MS link', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Reminder: team standup at 10 am tomorrow. Join here: https://teams.microsoft.com/l/meetup-join/198739. See you there!' } },

    { name: 'Friendly courier update (no link)', minScore: 0, maxScore: 24, expectLevels: ['safe', 'low'], expectAttacks: [],
      input: { mode: 'message', text: 'Your Flipkart delivery for order No. 1234 will arrive between 2-4 pm today. Please keep your phone reachable.' } }
  ];
})(typeof globalThis !== 'undefined' ? globalThis : this);