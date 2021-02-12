new Chart(document.getElementById("bar-chart"), {
    type: barChartStyle,
    data: {
      labels: barChartLabels,
      datasets: [
        {
          label: legendText,
          backgroundColor: ChartColours,
          data: barChartValues
        }
      ]
    },
    options: {
      legend: { 
        display: displayLegend
    },
    scales: {
        yAxes: [{
            ticks: {
                beginAtZero:true
            }
        }]
    },
      title: {
        display: displayTitle,
        text: chartTitle
      }
    }
});
