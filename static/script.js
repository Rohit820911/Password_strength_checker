const passwordInput = document.getElementById("password");
const togglePasswordBtn = document.getElementById("togglePassword");
const meterFill = document.getElementById("meterFill");
const strengthLabel = document.getElementById("strengthLabel");
const strengthScore = document.getElementById("strengthScore");

const lengthCheck = document.getElementById("lengthCheck");
const uppercaseCheck = document.getElementById("uppercaseCheck");
const lowercaseCheck = document.getElementById("lowercaseCheck");
const numbersCheck = document.getElementById("numbersCheck");
const symbolsCheck = document.getElementById("symbolsCheck");
const patternCheck = document.getElementById("patternCheck");
const commonCheck = document.getElementById("commonCheck");

const entropyValue = document.getElementById("entropyValue");
const charsetValue = document.getElementById("charsetValue");
const offlineTime = document.getElementById("offlineTime");
const onlineTime = document.getElementById("onlineTime");

const suggestionsList = document.getElementById("suggestionsList");
const md5Value = document.getElementById("md5Value");
const sha256Value = document.getElementById("sha256Value");

const generateBtn = document.getElementById("generateBtn");
const genLength = document.getElementById("genLength");
const useUpper = document.getElementById("useUpper");
const useLower = document.getElementById("useLower");
const useDigits = document.getElementById("useDigits");
const useSymbols = document.getElementById("useSymbols");

let typingTimer = null;

function setMeter(score, label) {
  meterFill.style.width = `${score}%`;

  if (score < 40) {
    meterFill.style.background = "linear-gradient(90deg, #ff5c7a, #ff8a5c)";
  } else if (score < 75) {
    meterFill.style.background = "linear-gradient(90deg, #ffc857, #ff9f43)";
  } else {
    meterFill.style.background = "linear-gradient(90deg, #47e6a1, #53d6ff)";
  }

  strengthLabel.textContent = label;
  strengthScore.textContent = `${score} / 100`;
}

function setText(el, value) {
  el.textContent = value;
}

function renderSuggestions(items) {
  suggestionsList.innerHTML = "";
  if (!items || !items.length) {
    const li = document.createElement("li");
    li.textContent = "No suggestions.";
    suggestionsList.appendChild(li);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    suggestionsList.appendChild(li);
  });
}

async function analyzePassword(password) {
  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    const data = await response.json();

    setMeter(data.score, data.strength);

    setText(lengthCheck, data.checks.length);
    setText(uppercaseCheck, data.checks.uppercase);
    setText(lowercaseCheck, data.checks.lowercase);
    setText(numbersCheck, data.checks.numbers);
    setText(symbolsCheck, data.checks.special_characters);
    setText(patternCheck, data.checks.repeated_patterns);
    setText(commonCheck, data.checks.common_password);

    setText(entropyValue, data.entropy.toFixed(2));
    setText(charsetValue, data.charset_size);
    setText(offlineTime, data.crack_time.offline_readable);
    setText(onlineTime, data.crack_time.online_readable);

    setText(md5Value, data.hashes.md5 || "-");
    setText(sha256Value, data.hashes.sha256 || "-");

    renderSuggestions(data.suggestions);
  } catch (error) {
    console.error("Analysis failed:", error);
  }
}

async function generatePassword() {
  try {
    const response = await fetch("/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        length: Number(genLength.value) || 16,
        use_upper: useUpper.checked,
        use_lower: useLower.checked,
        use_digits: useDigits.checked,
        use_symbols: useSymbols.checked,
      }),
    });

    const data = await response.json();
    passwordInput.value = data.password;
    passwordInput.type = "text";
    togglePasswordBtn.textContent = "Hide";
    await analyzePassword(data.password);
  } catch (error) {
    console.error("Generate failed:", error);
  }
}

togglePasswordBtn.addEventListener("click", () => {
  const hidden = passwordInput.type === "password";
  passwordInput.type = hidden ? "text" : "password";
  togglePasswordBtn.textContent = hidden ? "Hide" : "Show";
});

passwordInput.addEventListener("input", () => {
  clearTimeout(typingTimer);
  typingTimer = setTimeout(() => analyzePassword(passwordInput.value), 120);
});

generateBtn.addEventListener("click", generatePassword);

window.addEventListener("load", () => {
  analyzePassword(passwordInput.value || "");
});
