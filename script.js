const sections = document.querySelectorAll(".section");
const navItems = document.querySelectorAll(".nav-item");
const pageTitle = document.getElementById("page-title");

const titles = {
  dashboard: "Phishing Awareness Training",
  phishing: "What is Phishing?",
  examples: "Spot the Phish",
  websites: "Recognizing Fake Websites",
  social: "Social Engineering Tactics",
  checklist: "Safety Checklist",
  quiz: "Interactive Knowledge Check"
};

function showSection(id) {
  sections.forEach(section => section.classList.toggle("active", section.id === id));
  navItems.forEach(item => item.classList.toggle("active", item.dataset.section === id));
  pageTitle.textContent = titles[id] || "Phishing Awareness Training";
  window.scrollTo({ top: 0, behavior: "smooth" });
}

navItems.forEach(item => {
  item.addEventListener("click", () => showSection(item.dataset.section));
});

document.querySelectorAll("[data-go]").forEach(button => {
  button.addEventListener("click", () => showSection(button.dataset.go));
});

const questions = [
  {
    text: "Which is the strongest warning sign in a suspicious email?",
    options: ["A professional logo", "A request using urgency and pressure", "A short greeting", "A normal signature"],
    answer: 1,
    explanation: "Urgency and pressure are common manipulation tactics. Pause and verify before acting."
  },
  {
    text: "What should you do with an unexpected password-reset email?",
    options: ["Click the link immediately", "Reply with your password", "Open the official service manually", "Forward it to friends"],
    answer: 2,
    explanation: "Use the official app or manually typed website instead of the email link."
  },
  {
    text: "Does HTTPS alone prove that a website is legitimate?",
    options: ["Yes", "No", "Only on mobile", "Only for banks"],
    answer: 1,
    explanation: "HTTPS encrypts the connection but does not prove the domain belongs to a trusted organization."
  },
  {
    text: "Which tactic says your account will close unless you act now?",
    options: ["Curiosity", "Urgency", "Reward", "Familiarity"],
    answer: 1,
    explanation: "Urgency creates pressure and discourages careful verification."
  },
  {
    text: "What is the safest way to verify an unusual payment request?",
    options: ["Use the phone number in the message", "Reply to the same email", "Use a trusted, separate contact channel", "Pay a small amount first"],
    answer: 2,
    explanation: "Use a known phone number, official app, or established internal process."
  },
  {
    text: "What is smishing?",
    options: ["Phishing through SMS messages", "Phishing through websites only", "A type of antivirus", "A password manager"],
    answer: 0,
    explanation: "Smishing is phishing delivered through text messages."
  },
  {
    text: "What should you do if you clicked a suspicious link?",
    options: ["Ignore it", "Report it promptly and follow incident-response guidance", "Share it with others", "Disable security software"],
    answer: 1,
    explanation: "Prompt reporting allows security teams to reduce damage and protect others."
  },
  {
    text: "Which habit is most effective against phishing?",
    options: ["Trust familiar logos", "Act quickly", "Stop, inspect, and verify", "Use the same password everywhere"],
    answer: 2,
    explanation: "A deliberate pause and independent verification are core anti-phishing habits."
  }
];

const quizContainer = document.getElementById("quiz-container");

function renderQuiz() {
  quizContainer.innerHTML = questions.map((q, i) => `
    <div class="question">
      <h4>${i + 1}. ${q.text}</h4>
      ${q.options.map((option, j) => `
        <label class="option">
          <input type="radio" name="q${i}" value="${j}">
          ${option}
        </label>
      `).join("")}
    </div>
  `).join("");
}

renderQuiz();

document.getElementById("submit-quiz").addEventListener("click", () => {
  let score = 0;
  let unanswered = 0;

  questions.forEach((q, i) => {
    const selected = document.querySelector(`input[name="q${i}"]:checked`);
    if (!selected) {
      unanswered++;
    } else if (Number(selected.value) === q.answer) {
      score++;
    }
  });

  const result = document.getElementById("quiz-result");
  result.classList.remove("hidden");

  if (unanswered > 0) {
    result.innerHTML = `<strong>Please answer all questions.</strong>You still have ${unanswered} unanswered question(s).`;
    return;
  }

  const percentage = Math.round((score / questions.length) * 100);
  let message = percentage >= 80
    ? "Excellent work. You demonstrated strong phishing-awareness knowledge."
    : percentage >= 60
      ? "Good effort. Review the modules once more to strengthen your understanding."
      : "Keep learning. Revisit the warning signs, verification steps, and safety checklist.";

  result.innerHTML = `<strong>${score}/${questions.length} correct — ${percentage}%</strong>${message}`;
  document.getElementById("retry-quiz").classList.remove("hidden");
  result.scrollIntoView({ behavior: "smooth", block: "center" });
});

document.getElementById("retry-quiz").addEventListener("click", () => {
  renderQuiz();
  document.getElementById("quiz-result").classList.add("hidden");
  document.getElementById("retry-quiz").classList.add("hidden");
  window.scrollTo({ top: 0, behavior: "smooth" });
});
