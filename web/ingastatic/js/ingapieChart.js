
new Chart(document.getElementById("doughnut-chart"), {
    type: 'doughnut',
    data: {
      labels: chartLabels,
      datasets: [
        {
        backgroundColor: ChartColours,

          data: pieChartData
        }
      ]
    },
    options: {
        cutoutPercentage: cutoutPercentage,
        legend: {
                display: displayLegend,
                position: 'bottom',
                labels: {
                    fontColor: "black",
                    fontSize: 12
                }
            },        
      title: {
        display: displayTitle,
        fontSize: 16,
        fontColor: "black",
        text: pieTitle
      }
    }
});