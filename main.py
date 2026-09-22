import os
import re
import secrets
import string
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes

# ============================================================
# CONFIGURATION
# ============================================================
TOKEN = os.environ.get("TELEGRAM_TOKEN")

if not TOKEN:
    raise ValueError("TELEGRAM_TOKEN environment variable is required.")

# ============================================================
# PASSWORD GENERATION (CSPRNG via secrets)
# ============================================================
def generate_password(length=16, use_upper=True, use_digits=True, use_symbols=True):
    """Generate a cryptographically secure password."""
    chars = string.ascii_lowercase
    
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{};:,.?"
    
    if length < 8:
        length = 8
    if length > 64:
        length = 64
    
    # Ensure at least one of each required class
    password = []
    if use_upper:
        password.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        password.append(secrets.choice(string.digits))
    if use_symbols:
        password.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.?"))
    
    # Fill the rest
    remaining = length - len(password)
    for _ in range(remaining):
        password.append(secrets.choice(chars))
    
    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password)
    return "".join(password)

# ============================================================
# PASSWORD STRENGTH CHECKER
# ============================================================
def check_strength(password):
    """Analyze password strength and return score + feedback."""
    score = 0
    feedback = []
    
    # Length check
    length = len(password)
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters.")
    
    # Character variety
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")
    
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")
    
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add digits.")
    
    if re.search(r"[!@#$%^&*()_\-+=\[\]{};:,.?]", password):
        score += 1
    else:
        feedback.append("Add special characters.")
    
    # Common password patterns
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
    if any(c in password.lower() for c in common):
        score = max(0, score - 2)
        feedback.append("Avoid common words.")
    
    # Sequences
    if re.search(r"(abc|123|qwe)", password.lower()):
        score = max(0, score - 1)
        feedback.append("Avoid sequences like 'abc' or '123'.")
    
    # Map score to label (max possible = 6)
    if score >= 5:
        label = "Very Strong"
    elif score >= 4:
        label = "Strong"
    elif score >= 3:
        label = "Moderate"
    elif score >= 2:
        label = "Weak"
    else:
        label = "Very Weak"
    
    return {"score": score, "max": 6, "label": label, "feedback": feedback}

# ============================================================
# TELEGRAM HANDLERS
# ============================================================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    keyboard = [
        [InlineKeyboardButton("Generate Password", callback_data="generate")],
        [InlineKeyboardButton("Check Strength", callback_data="check")],
        [InlineKeyboardButton("Security Tips", callback_data="tips")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "Welcome. I can generate secure passwords and check password strength.\n"
        "Use the buttons below or send me a password to analyze it.",
        reply_markup=reply_markup
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /help command."""
    await update.message.reply_text(
        "Available commands:\n"
        "/start - Main menu\n"
        "/help - Show this message\n"
        "/settings - View current settings\n\n"
        "You can also send any password directly to check its strength."
    )

async def settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /settings command."""
    await update.message.reply_text(
        "Current password generation settings:\n"
        "• Length: 16 characters\n"
        "• Uppercase: Yes\n"
        "• Digits: Yes\n"
        "• Symbols: Yes\n\n"
        "Send /generate to create a password."
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline button presses."""
    query = update.callback_query
    await query.answer()
    
    if query.data == "generate":
        password = generate_password(length=16)
        await query.edit_message_text(
            f"Generated password:\n`{password}`\n\n"
            f"Length: {len(password)} characters",
            parse_mode="Markdown"
        )
    
    elif query.data == "check":
        await query.edit_message_text(
            "Send me any password and I will check its strength.\n"
            "I do not store or log passwords."
        )
    
    elif query.data == "tips":
        await query.edit_message_text(
            "Security Tips:\n\n"
            "• Use at least 12 characters\n"
            "• Mix uppercase, lowercase, digits, and symbols\n"
            "• Avoid common words and sequences\n"
            "• Never reuse passwords across sites\n"
            "• Use a password manager"
        )

async def handle_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze a password sent by the user."""
    password = update.message.text
    
    # Ignore commands
    if password.startswith("/"):
        return
    
    result = check_strength(password)
    
    response = (
        f"Strength: {result['label']} ({result['score']}/{result['max']})\n\n"
    )
    
    if result['feedback']:
        response += "Suggestions:\n"
        for tip in result['feedback']:
            response += f"• {tip}\n"
    else:
        response += "This password looks good."
    
    await update.message.reply_text(response)

# ============================================================
# MAIN
# ============================================================
def main():
    app = Application.builder().token(TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("settings", settings))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_password))
    
    print("Bot is running with long polling...")
    app.run_polling()

if __name__ == "__main__":
    main()
