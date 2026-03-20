import jsPDF from 'jspdf';
import html2canvas from 'html2canvas-pro';

export async function exportReportToPdf(elementId: string, filename: string): Promise<void> {
  const element = document.getElementById(elementId);
  if (!element) return;

  const canvas = await html2canvas(element, {
    scale: 2,
    useCORS: true,
    logging: false,
    backgroundColor: '#ffffff',
  });

  const imgData = canvas.toDataURL('image/png');
  const pdf = new jsPDF('p', 'mm', 'a4');
  const pdfWidth = pdf.internal.pageSize.getWidth();
  const pdfHeight = pdf.internal.pageSize.getHeight();
  const imgWidth = pdfWidth - 20;
  const imgHeight = (canvas.height * imgWidth) / canvas.width;

  let heightLeft = imgHeight;
  let position = 10;

  pdf.addImage(imgData, 'PNG', 10, position, imgWidth, imgHeight);
  heightLeft -= (pdfHeight - 20);

  while (heightLeft > 0) {
    position = -(imgHeight - heightLeft) + 10;
    pdf.addPage();
    pdf.addImage(imgData, 'PNG', 10, position, imgWidth, imgHeight);
    heightLeft -= (pdfHeight - 20);
  }

  pdf.save(filename);
}
