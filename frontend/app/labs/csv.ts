// Parses quoted CSV, including escaped quotes and newlines in generator JSON.
export function parseCSV(text: string): string[][] {
 const rows: string[][]=[];let row:string[]=[];let value="";let quoted=false;
 for(let i=0;i<text.length;i++){
  const char=text[i];
  if(char==='"'){if(quoted && text[i+1]==='"'){value+='"';i++;}else quoted=!quoted;}
  else if(char==="," && !quoted){row.push(value);value="";}
  else if((char==="\n" || char==="\r") && !quoted){if(char==="\r" && text[i+1]==="\n")i++;row.push(value);if(row.some(cell=>cell!==""))rows.push(row);row=[];value="";}
  else value+=char;
 }
 if(quoted)throw new Error("Capture metadata has an unfinished quoted field.");
 if(value || row.length){row.push(value);rows.push(row);}
 return rows;
}
