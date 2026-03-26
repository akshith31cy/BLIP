// ================================
// DASHBOARD.JS
// Handles dashboard interactivity,
// user info display, and logout logic
// ================================

document.addEventListener("DOMContentLoaded", () => {
  console.log("✅ Dashboard loaded");

  // Display welcome message if username stored
  const username = window.localStorage.getItem("username");
  if (username) {
    const userWelcome = document.getElementById("user-welcome");
    if (userWelcome) {
      userWelcome.textContent = `Welcome, ${username}!`;
    }
  }

  // Fetch user stats from Flask backend
  fetch("/api/user_stats")
    .then((response) => {
      if (!response.ok) {
        throw new Error("Failed to fetch user data");
      }
      return response.json();
    })
    .then((data) => {
      console.log("📊 User data:", data);

      // Update stat cards with real data
      document.getElementById("total-users").textContent = data.total_users || 0;
      document.getElementById("active-users").textContent = data.active_users || 0;
      document.getElementById("compromised-accounts").textContent = data.compromised_accounts || 0;
      document.getElementById("success-rate").textContent = (data.success_rate || 0) + "%";
      document.getElementById("honey-entries").textContent = data.total_honey_entries || 0;
      document.getElementById("decoy-ratio").textContent = data.decoy_ratio || 0;

      // Create chart
      createChart(data);
    })
    .catch((err) => {
      console.error("Error fetching stats:", err);
      document.getElementById("stats-container").innerHTML = 
        '<p style="color: red;">Error loading statistics. Please refresh the page.</p>';
    });

  // Logout button handler
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      window.localStorage.removeItem("username");
      
      fetch("/logout", { method: "POST" })
        .then(() => {
          window.location.href = "/";
        })
        .catch((err) => {
          console.error("Logout failed:", err);
          // Redirect anyway
          window.location.href = "/";
        });
    });
  }
});

function createChart(data) {
  const ctx = document.getElementById("metricsChart");
  if (!ctx) return;

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["Total Users", "Active", "Compromised", "Honey Entries"],
      datasets: [{
        label: "Statistics",
        data: [
          data.total_users || 0,
          data.active_users || 0,
          data.compromised_accounts || 0,
          data.total_honey_entries || 0
        ],
        backgroundColor: [
          "rgba(54, 162, 235, 0.6)",
          "rgba(75, 192, 192, 0.6)",
          "rgba(255, 99, 132, 0.6)",
          "rgba(255, 206, 86, 0.6)"
        ],
        borderColor: [
          "rgba(54, 162, 235, 1)",
          "rgba(75, 192, 192, 1)",
          "rgba(255, 99, 132, 1)",
          "rgba(255, 206, 86, 1)"
        ],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      scales: {
        y: {
          beginAtZero: true
        }
      },
      plugins: {
        legend: {
          display: false
        },
        title: {
          display: true,
          text: "LEAP System Metrics"
        }
      }
    }
  });
}