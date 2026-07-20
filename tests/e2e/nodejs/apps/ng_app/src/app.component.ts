import { Component } from "@angular/core";

@Component({
  selector: "app-root",
  standalone: true,
  template: "<h1>Hello {{ name }} from the e2e Angular app</h1>",
})
export class AppComponent {
  name = "e2e";

  increment(value: number): number {
    return value + 1;
  }
}
