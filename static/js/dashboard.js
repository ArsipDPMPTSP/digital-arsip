document.addEventListener("DOMContentLoaded", function () {
  const dataEl = document.getElementById("ringkasan-data");
  let data = {};

  if (dataEl) {
    try {
      data = JSON.parse(dataEl.textContent);
    } catch (e) {
      console.error("Gagal parse ringkasan-data:", e);
    }
  }

  const ctx = document.getElementById("chartRingkasan");
  if (ctx) {
    new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Total Dokumen", "Total Kategori", "Ukuran File (KB)"],
        datasets: [
          {
            data: [data.total_docs || 0, data.total_cat || 0, data.total_size || 0],
            backgroundColor: ["#0d6efd", "#198754", "#ffc107"],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: "bottom" },
          tooltip: {
            callbacks: {
              label: function (context) {
                return `${context.label}: ${context.parsed}`;
              },
            },
          },
        },
        cutout: "60%",
      },
    });
  }
});
