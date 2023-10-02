export function generateNumberString(len: number = 6) {
  var numberString = ''
  for (var i = 0; i < len; i++) {
    var digit = Math.floor(Math.random() * 10)
    numberString += digit.toString()
  }
  return numberString
}
