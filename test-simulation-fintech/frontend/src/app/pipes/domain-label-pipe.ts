import { Pipe, PipeTransform } from '@angular/core';

@Pipe({
  name: 'domainLabel',
  standalone: false,
})
export class DomainLabelPipe implements PipeTransform {
  transform(value: unknown, ...args: unknown[]): unknown {
    return null;
  }
}
