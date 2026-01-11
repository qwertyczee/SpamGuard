// ============================================================================
// Test Fixtures - Spam and Ham Email Samples
// Based on real-world spam patterns and legitimate email patterns
// ============================================================================

import type { EmailInput } from "../../src/types";

// ============================================================================
// SPAM SAMPLES
// ============================================================================

export const SPAM_EMAILS: Array<{
    name: string;
    email: EmailInput;
    expectedMinScore: number;
}> = [
    {
        name: "Nigerian Prince Scam",
        email: {
            from: "prince.abubakar@gmail.com",
            to: "victim@example.com",
            subject: "URGENT: Inheritance Fund Transfer - $4.5 Million USD",
            textBody: `
Dear Friend,

I am Prince Abubakar, the son of the late King of Nigeria. My father left behind an inheritance of $4,500,000 (Four Million Five Hundred Thousand US Dollars) before his untimely death.

Due to the political situation in my country, I need a trusted foreign partner to help me transfer this fund out of Nigeria. In return, you will receive 30% of the total amount.

Please respond urgently with your:
- Full Name
- Bank Account Details
- Phone Number

This is strictly confidential. Do not share with anyone.

Awaiting your urgent response.

Prince Abubakar
      `,
            headers: {
                "received-spf": "fail",
            },
        },
        expectedMinScore: 8,
    },

    {
        name: "Lottery Scam",
        email: {
            from: "lottery@winner-notification.xyz",
            to: "lucky@example.com",
            subject: "CONGRATULATIONS!!! YOU HAVE WON $1,000,000!!!",
            textBody: `
CONGRATULATIONS WINNER!!!

Your email address has been selected as the LUCKY WINNER of our international lottery program!

You have won: $1,000,000.00 USD (One Million US Dollars)

Ticket Number: 475-6839-4857-38
Reference Number: BTL/491OYI/02
Batch Number: 12/25/0340

To claim your prize, contact our claims agent immediately:

Dr. James Williams
Email: claims@winner-lottery.tk
Phone: +44-703-123-4567

ACT NOW! This offer expires in 48 hours!

You must pay a small processing fee of $500 to receive your winnings.

DO NOT IGNORE THIS MESSAGE!
      `,
        },
        expectedMinScore: 12,
    },

    {
        name: "Phishing - PayPal",
        email: {
            from: "security@paypa1-secure.com",
            to: "user@example.com",
            subject: "Your PayPal Account Has Been Suspended - Verify Now",
            htmlBody: `
<html>
<body>
<div style="font-family: Arial, sans-serif;">
  <img src="https://fake-paypal.com/logo.png" width="150">
  <h2>Your account has been limited</h2>
  <p>Dear Valued Customer,</p>
  <p>We have noticed <strong>unusual activity</strong> on your PayPal account. Your account has been temporarily suspended.</p>
  <p>To restore access to your account, please verify your identity by clicking the button below:</p>
  <a href="http://192.168.1.1/paypal-login" style="background: #0070ba; color: white; padding: 10px 20px; text-decoration: none;">
    Verify Your Account
  </a>
  <p>If you do not verify within 24 hours, your account will be permanently closed.</p>
  <p>Thank you,<br>PayPal Security Team</p>
</div>
<img src="https://tracking.spammer.com/pixel.gif" width="1" height="1">
</body>
</html>
      `,
            headers: {
                "authentication-results": "dkim=fail; spf=softfail",
            },
        },
        expectedMinScore: 10,
    },

    {
        name: "Pharma Spam",
        email: {
            from: "discount-meds@canadian-pharmacy.top",
            to: "customer@example.com",
            subject: "V1AGRA and C1ALIS - 90% OFF - No Prescription Needed!!!",
            textBody: `
CANADIAN PHARMACY - LOWEST PRICES GUARANTEED!

Buy Viagra, Cialis, and more WITHOUT PRESCRIPTION!

SPECIAL OFFER:
- V1agra 100mg - $0.99 per pill
- C1alis 20mg - $1.49 per pill
- Weight Loss Pills - $29.99

FREE SHIPPING on orders over $100!

Order now at: http://cheap-pills-rx.gq/order

100% Satisfaction Guaranteed!
No prescription required!
Discreet packaging!

CLICK HERE TO ORDER NOW!!!

To unsubscribe, reply with "REMOVE" in subject line.
      `,
        },
        expectedMinScore: 12,
    },

    {
        name: "Crypto Scam",
        email: {
            from: "elon@tesla-crypto-giveaway.click",
            to: "investor@example.com",
            subject: "Elon Musk Bitcoin Giveaway - Double Your BTC!",
            textBody: `
🚀 OFFICIAL TESLA CRYPTOCURRENCY GIVEAWAY 🚀

Elon Musk is giving away $100,000,000 in Bitcoin!

To participate, simply send any amount of Bitcoin to the address below, and we will send back DOUBLE!

Send 0.1 BTC → Receive 0.2 BTC
Send 1 BTC → Receive 2 BTC  
Send 10 BTC → Receive 20 BTC

Bitcoin Wallet: 1A2B3C4D5E6F7G8H9I0J

This is a limited time offer! Only the first 1000 participants will receive the bonus.

ACT NOW before it's too late!

Terms and conditions apply. This is not a scam.
      `,
        },
        expectedMinScore: 10,
    },

    {
        name: "Romance Scam",
        email: {
            from: "beautiful.anna@dating-site.ru",
            to: "lonely@example.com",
            subject: "Beautiful woman seeking true love",
            textBody: `
Hello my dear!

I am Anna, a beautiful single woman from Russia looking for a serious relationship.

I found your profile on the internet and felt an immediate connection. I am 28 years old, 
slim, with blonde hair and blue eyes. I am lonely and seeking my soulmate.

I want to know everything about you! Please write me back and tell me about yourself.

I have many photos to share with you. Just visit my profile at: http://hot-russian-women.ml/anna

I am waiting for your message with hope in my heart!

With love,
Anna
      `,
        },
        expectedMinScore: 4.5,
    },

    {
        name: "Work From Home Scam",
        email: {
            from: "careers@easy-money-jobs.work",
            to: "jobseeker@example.com",
            subject:
                "Make $5000/Week Working From Home - No Experience Required!",
            textBody: `
ARE YOU TIRED OF YOUR BORING 9-5 JOB?

Discover how ordinary people are making $5000+ per week working from home!

✅ No experience required
✅ Work your own hours
✅ Be your own boss
✅ Financial freedom guaranteed

JOIN NOW and receive:
- FREE training materials
- Personal mentor
- Unlimited earning potential

LIMITED SPOTS AVAILABLE!

Click here to claim your spot: http://work-at-home-riches.biz/join

Don't miss this LIFE-CHANGING opportunity!

Many people have already quit their jobs and achieved FINANCIAL FREEDOM!

Sign up now - only 50 spots remaining!
      `,
        },
        expectedMinScore: 9,
    },

    {
        name: "Hidden Text HTML Spam",
        email: {
            from: "promo@special-deals.icu",
            to: "user@example.com",
            subject: "Special Offer Inside",
            htmlBody: `
<html>
<body>
<div style="display:none">This text is hidden and contains random words to bypass filters: 
meeting project deadline schedule attached regards sincerely documentation repository</div>
<div style="font-size:0px;color:#ffffff">More hidden spam filter bypass text here</div>
<h1>AMAZING DEAL - 95% OFF!</h1>
<p>Buy now and save BIG MONEY!</p>
<p style="visibility:hidden">Hidden text: test project meeting schedule</p>
<a href="http://scam-site.xyz/buy">CLICK HERE NOW!!!</a>
<!-- random words to confuse bayesian filters: documentation sincerely regards meeting project -->
<!-- more random: repository commit merge branch deploy -->
<!-- even more: test debug error bug fix -->
</body>
</html>
      `,
        },
        expectedMinScore: 6,
    },

    {
        name: "Obfuscated Viagra Spam",
        email: {
            from: "pills@med-store.gq",
            to: "customer@example.com",
            subject: 'V.I" + "A.G" + "R.A - S.p" + "e.c.i.a.l O.f.f.e.r',
            textBody: `
V  I  A  G  R  A

C  I  A  L  I  S

L  E  V  I  T  R  A

Best prices! No prescription needed!

Visit: hxxp://pills-cheap[.]ml/order

F.R" + "E.E S.H" + "I.P.P" + "I.N.G!
      `,
        },
        expectedMinScore: 5,
    },

    {
        name: "Advance Fee Fraud",
        email: {
            from: "barrister.john@legal-firm.cf",
            to: "beneficiary@example.com",
            subject: "Re: Your Pending Fund Transfer - Action Required",
            textBody: `
Dear Beneficiary,

I am Barrister John Williams, a solicitor representing the estate of the late Mr. Robert Thompson who died in a car accident with his wife and children.

Before his death, Mr. Thompson deposited $8,500,000 (Eight Million Five Hundred Thousand USD) in a trunk box with a security company.

My investigation reveals you share the same surname as my late client. I am proposing that you stand as the next of kin to claim this fund.

For your assistance, you will receive 40% of the total sum.

This transaction is 100% risk-free and legal.

Please respond with:
1. Your full name
2. Your private phone number
3. Your occupation
4. Your age

I await your urgent response.

Regards,
Barrister John Williams
Legal Practitioner
      `,
        },
        expectedMinScore: 11,
    },
];

// ============================================================================
// HAM SAMPLES (Legitimate Emails)
// ============================================================================

export const HAM_EMAILS: Array<{
    name: string;
    email: EmailInput;
    expectedMaxScore: number;
}> = [
    {
        name: "Business Meeting Request",
        email: {
            from: "john.smith@company.com",
            to: "jane.doe@company.com",
            subject: "Re: Q4 Planning Meeting - Tuesday 2pm",
            textBody: `
Hi Jane,

Thanks for sending over the agenda for Tuesday's meeting. I've reviewed the quarterly projections and have a few questions we should discuss.

Could we add 15 minutes to cover the new product launch timeline? I'd like to make sure we're aligned on the marketing strategy before we finalize the budget.

I've attached the updated spreadsheet with my comments.

See you Tuesday!

Best regards,
John

John Smith
Senior Product Manager
Company Inc.
      `,
            headers: {
                "received-spf": "pass",
                "dkim-signature": "v=1; a=rsa-sha256; d=company.com",
                "authentication-results": "dkim=pass; spf=pass; dmarc=pass",
            },
        },
        expectedMaxScore: 2,
    },

    {
        name: "GitHub Notification",
        email: {
            from: "notifications@github.com",
            to: "developer@example.com",
            subject:
                "[repo/project] Pull Request #142: Fix memory leak in cache module",
            textBody: `
@developer requested your review on this pull request.

Fix memory leak in cache module (#142)

This PR fixes the memory leak issue reported in #138. The problem was caused by 
circular references in the cache invalidation logic.

Changes:
- Refactored cache invalidation to use weak references
- Added unit tests for the new implementation
- Updated documentation

Files changed: 4
Additions: 127
Deletions: 45

View the pull request: https://github.com/repo/project/pull/142

You can reply to this email directly or view it on GitHub.
      `,
            headers: {
                "received-spf": "pass",
                "dkim-signature": "v=1; a=rsa-sha256; d=github.com",
            },
        },
        expectedMaxScore: 2,
    },

    {
        name: "Order Confirmation",
        email: {
            from: "orders@amazon.com",
            to: "customer@example.com",
            subject: "Your Amazon.com order #112-4567890-1234567",
            htmlBody: `
<html>
<body style="font-family: Arial, sans-serif;">
<h2>Order Confirmation</h2>
<p>Hello Customer,</p>
<p>Thank you for your order. We'll send a confirmation when your items ship.</p>

<h3>Order Details</h3>
<table>
<tr><td>Order #:</td><td>112-4567890-1234567</td></tr>
<tr><td>Order Date:</td><td>January 10, 2025</td></tr>
<tr><td>Order Total:</td><td>$49.99</td></tr>
</table>

<h3>Shipping Address</h3>
<p>John Doe<br>123 Main Street<br>Anytown, ST 12345</p>

<h3>Items Ordered</h3>
<p>Wireless Bluetooth Headphones - $49.99</p>

<p>Track your package: <a href="https://amazon.com/orders">View order status</a></p>

<p>Thank you for shopping with us!</p>
<p>Amazon.com</p>
</body>
</html>
      `,
            headers: {
                "received-spf": "pass",
                "authentication-results": "dkim=pass; spf=pass",
            },
        },
        expectedMaxScore: 3,
    },

    {
        name: "Password Reset Request",
        email: {
            from: "no-reply@accounts.google.com",
            to: "user@gmail.com",
            subject: "Password reset request for your Google Account",
            textBody: `
Hello,

We received a request to reset the password for your Google Account (user@gmail.com).

If you made this request, click the link below to reset your password:
https://accounts.google.com/reset/verify?token=abc123

This link will expire in 24 hours.

If you didn't request a password reset, you can ignore this email. Your password will not be changed.

This is an automated message from Google. Please do not reply to this email.

The Google Accounts Team
      `,
            headers: {
                "received-spf": "pass",
                "dkim-signature": "v=1; a=rsa-sha256; d=accounts.google.com",
                "authentication-results": "dkim=pass; spf=pass; dmarc=pass",
            },
        },
        expectedMaxScore: 3,
    },

    {
        name: "Newsletter Subscription",
        email: {
            from: "newsletter@techblog.com",
            to: "subscriber@example.com",
            subject: "Weekly Tech Digest - January Edition",
            htmlBody: `
<html>
<body>
<h1>Weekly Tech Digest</h1>
<p>Hi there,</p>
<p>Here's your weekly roundup of the top tech news:</p>

<h2>This Week's Top Stories</h2>
<ul>
<li><a href="https://techblog.com/ai-advances">New Advances in AI Research</a></li>
<li><a href="https://techblog.com/cloud-computing">Cloud Computing Trends for 2025</a></li>
<li><a href="https://techblog.com/security-tips">10 Security Tips for Developers</a></li>
</ul>

<h2>Featured Tutorial</h2>
<p>Learn how to build a REST API with Node.js and Express.</p>
<a href="https://techblog.com/tutorial">Read the tutorial</a>

<p>Best regards,<br>The Tech Blog Team</p>

<hr>
<p style="font-size: 12px;">
You received this email because you subscribed to our newsletter.<br>
<a href="https://techblog.com/unsubscribe">Unsubscribe</a> | 
<a href="https://techblog.com/preferences">Update preferences</a>
</p>
</body>
</html>
      `,
            headers: {
                "received-spf": "pass",
                "list-unsubscribe": "<https://techblog.com/unsubscribe>",
            },
        },
        expectedMaxScore: 3.5,
    },

    {
        name: "Calendar Invite",
        email: {
            from: "calendar-notification@google.com",
            to: "attendee@example.com",
            subject: "Invitation: Team Standup @ Weekly on Mondays 9:00am",
            textBody: `
You have been invited to the following event.

Team Standup
When: Weekly on Mondays 9:00am - 9:30am (EST)
Where: Conference Room B / Google Meet

Calendar: attendee@example.com
Who:
  - organizer@example.com - organizer
  - attendee@example.com
  - colleague@example.com

Going? Yes - Maybe - No

View your event at https://calendar.google.com/event?id=abc123

Invitation from Google Calendar

You are receiving this email because you are an attendee of this event.
      `,
            headers: {
                "received-spf": "pass",
                "dkim-signature": "v=1; a=rsa-sha256; d=google.com",
            },
        },
        expectedMaxScore: 2,
    },

    {
        name: "Personal Email",
        email: {
            from: "mom@gmail.com",
            to: "kid@gmail.com",
            subject: "Dinner on Sunday?",
            textBody: `
Hi honey,

Just wanted to check if you're still coming over for dinner on Sunday? Dad is planning to grill some steaks.

Let me know if you have any dietary restrictions these days - I remember you mentioned trying to eat less red meat.

Also, don't forget Grandma's birthday is coming up next week. Should we plan something together?

Love you!
Mom

P.S. The dog misses you :)
      `,
            headers: {
                "received-spf": "pass",
            },
        },
        expectedMaxScore: 2.5,
    },

    {
        name: "Invoice Email",
        email: {
            from: "billing@freelancer.com",
            to: "client@company.com",
            subject: "Invoice #2024-001 for Website Development Services",
            textBody: `
Dear Client,

Please find attached invoice #2024-001 for the website development services provided in December 2024.

Invoice Summary:
- Website Design & Development: $3,500.00
- Hosting Setup: $200.00
- Total Due: $3,700.00

Payment is due within 30 days. You can pay via bank transfer using the details on the invoice, or through our payment portal.

If you have any questions about this invoice, please don't hesitate to reach out.

Thank you for your business!

Best regards,
Jane Freelancer
Web Developer
jane@freelancer.com
      `,
            headers: {
                "received-spf": "pass",
            },
        },
        expectedMaxScore: 3,
    },

    {
        name: "Shipping Notification",
        email: {
            from: "shipping@fedex.com",
            to: "recipient@example.com",
            subject: "Your package is on the way - Tracking #789456123",
            htmlBody: `
<html>
<body>
<h2>Your package is on the way!</h2>
<p>Good news! Your FedEx package is on its way.</p>

<table>
<tr><td><strong>Tracking Number:</strong></td><td>789456123</td></tr>
<tr><td><strong>Estimated Delivery:</strong></td><td>Friday, January 12, 2025</td></tr>
<tr><td><strong>Ship Date:</strong></td><td>January 9, 2025</td></tr>
<tr><td><strong>Service:</strong></td><td>FedEx Ground</td></tr>
</table>

<p><a href="https://fedex.com/track?num=789456123">Track your package</a></p>

<h3>Delivery Address</h3>
<p>John Doe<br>123 Main St<br>Anytown, ST 12345</p>

<p>Thank you for choosing FedEx!</p>
</body>
</html>
      `,
            headers: {
                "received-spf": "pass",
                "authentication-results": "dkim=pass; spf=pass",
            },
        },
        expectedMaxScore: 3,
    },

    {
        name: "Support Ticket Response",
        email: {
            from: "support@software.com",
            to: "customer@example.com",
            subject: "Re: [Ticket #45678] Login issue resolved",
            textBody: `
Hi,

Thank you for contacting our support team.

I've looked into the login issue you reported and found that the problem was caused by a cached session token. I've cleared the cache on our end, and you should now be able to log in normally.

Please try the following:
1. Clear your browser cache
2. Close and reopen your browser
3. Navigate to https://software.com/login
4. Enter your credentials

If you continue to experience issues, please let me know and I'll be happy to investigate further.

Is there anything else I can help you with?

Best regards,
Sarah
Customer Support Team
Software Inc.

---
Ticket #45678 | Priority: Normal | Status: Resolved
      `,
            headers: {
                "received-spf": "pass",
            },
        },
        expectedMaxScore: 2.5,
    },
];

// ============================================================================
// EDGE CASES
// ============================================================================

export const EDGE_CASE_EMAILS: Array<{
    name: string;
    email: EmailInput;
    description: string;
}> = [
    {
        name: "Empty Email",
        email: {
            from: "",
            to: "",
            subject: "",
            textBody: "",
        },
        description: "Completely empty email should handle gracefully",
    },

    {
        name: "Very Long Email",
        email: {
            from: "sender@example.com",
            to: "recipient@example.com",
            subject: "Long content test",
            textBody: "Lorem ipsum ".repeat(10000),
        },
        description: "Very long email body should not crash",
    },

    {
        name: "Unicode Content",
        email: {
            from: "user@example.com",
            to: "recipient@example.com",
            subject: "日本語のメール 🎉",
            textBody: `
こんにちは！

This email contains mixed scripts:
- Japanese: 日本語
- Russian: Русский
- Arabic: العربية
- Emoji: 🎉🚀💯

Let's see how the filter handles this! 😊
      `,
        },
        description: "Unicode and emoji content",
    },

    {
        name: "Legitimate Marketing Email",
        email: {
            from: "marketing@legitimate-business.com",
            to: "subscriber@example.com",
            subject: "Special Offer: 20% off your next order",
            textBody: `
Dear valued customer,

As a thank you for being a loyal customer, we're offering you an exclusive 20% discount on your next order.

Use code: THANKS20 at checkout.

This offer is valid until the end of the month.

Best regards,
The Legitimate Business Team

To unsubscribe, click here: https://legitimate-business.com/unsubscribe
      `,
            headers: {
                "received-spf": "pass",
                "list-unsubscribe":
                    "<https://legitimate-business.com/unsubscribe>",
            },
        },
        description: "Marketing email that could trigger false positive",
    },

    {
        name: "Security Alert - Legitimate",
        email: {
            from: "security@bank.com",
            to: "customer@example.com",
            subject: "New sign-in to your account",
            textBody: `
We noticed a new sign-in to your account.

Date: January 10, 2025
Location: New York, USA
Device: iPhone

If this was you, you can ignore this email.

If this wasn't you, please secure your account immediately by visiting our website directly (don't click any links in emails) and changing your password.

For your security, we will never ask for your password via email.

Security Team
Bank Inc.
      `,
            headers: {
                "received-spf": "pass",
                "authentication-results": "dkim=pass; spf=pass; dmarc=pass",
            },
        },
        description: "Legitimate security alert that could look like phishing",
    },
];
