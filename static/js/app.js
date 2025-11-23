// Results page: table + Chart.js using /api/results
document.addEventListener("DOMContentLoaded", () => {
  const refreshBtn = document.getElementById("refreshResults");
  const resultsChartCanvas = document.getElementById("resultsChart");
  const partyChartCanvas = document.getElementById("partyChart");

  let resultsChartInstance = null;
  let partyChartInstance = null;

  async function loadResults() {
    try {
      const res = await fetch("/api/results");
      if (!res.ok) {
        console.error("Failed to load results from API");
        return;
      }
      const data = await res.json();
      const tbody = document.querySelector("#resultsTable tbody");
      if (tbody) {
        tbody.innerHTML = "";
        data.results.forEach((row, index) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>${index + 1}</td>
            <td>${row.name}</td>
            <td>${row.party || "Independent"}</td>
            <td>${row.votes}</td>
          `;
          tbody.appendChild(tr);
        });
      }

      // Candidate bar chart
      if (resultsChartCanvas && window.Chart) {
        const labels = data.results.map(r => r.name);
        const votes = data.results.map(r => r.votes);

        if (resultsChartInstance) {
          resultsChartInstance.destroy();
        }

        resultsChartInstance = new Chart(resultsChartCanvas, {
          type: "bar",
          data: {
            labels,
            datasets: [{
              label: "Votes",
              data: votes
            }]
          },
          options: {
            responsive: true,
            scales: {
              y: {
                beginAtZero: true,
                ticks: {
                  precision: 0
                }
              }
            }
          }
        });
      }

      // Party doughnut chart
      if (partyChartCanvas && window.Chart) {
        const partyMap = new Map();
        data.results.forEach(r => {
          const party = r.party || "Independent";
          partyMap.set(party, (partyMap.get(party) || 0) + r.votes);
        });
        const partyLabels = Array.from(partyMap.keys());
        const partyVotes = Array.from(partyMap.values());

        if (partyChartInstance) {
          partyChartInstance.destroy();
        }

        partyChartInstance = new Chart(partyChartCanvas, {
          type: "doughnut",
          data: {
            labels: partyLabels,
            datasets: [{
              data: partyVotes
            }]
          },
          options: {
            responsive: true,
            cutout: "55%"
          }
        });
      }
    } catch (err) {
      console.error(err);
    }
  }

  if (refreshBtn) {
    refreshBtn.addEventListener("click", loadResults);
    loadResults();
  }
});
